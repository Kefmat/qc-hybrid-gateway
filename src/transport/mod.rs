use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::crypto::{
    kdf::{derive_session_keys, hash_transcript, SessionKeys},
    kem::{decapsulate_hybrid, encapsulate_hybrid, HybridKemKeyPair},
    sig::{HybridSigKeyPair, HybridSigPublicKey},
};
use crate::protocol::{
    FrameDecoder, HandshakeInit, HandshakeResponse, PacketFrame, PacketType,
};
use crate::session::{Session, SessionMetrics};

/// Configuration for network tunnel endpoints.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub rekey_threshold: u64,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            rekey_threshold: 100_000,
        }
    }
}

/// Asynchronous Post-Quantum Hybrid Tunnel Server.
pub struct TunnelServer {
    pub sig_keys: HybridSigKeyPair,
    pub config: TunnelConfig,
}

impl TunnelServer {
    pub fn new(sig_keys: HybridSigKeyPair) -> Self {
        Self::with_config(sig_keys, TunnelConfig::default())
    }

    pub fn with_config(sig_keys: HybridSigKeyPair, config: TunnelConfig) -> Self {
        Self { sig_keys, config }
    }

    /// Handles a single TCP connection stream.
    pub async fn handle_connection(
        &self,
        stream: TcpStream,
        expected_client_sig_pk: Option<&HybridSigPublicKey>,
    ) -> Result<SessionMetrics, String> {
        self.handle_stream(stream, expected_client_sig_pk).await
    }

    /// Handles an asynchronous bidirectional stream, performing the PQC hybrid handshake and message loop.
    pub async fn handle_stream<S>(
        &self,
        mut stream: S,
        expected_client_sig_pk: Option<&HybridSigPublicKey>,
    ) -> Result<SessionMetrics, String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut decoder = FrameDecoder::new();
        let mut read_buf = [0u8; 4096];

        // 1. Read HandshakeInit from client
        let init_frame = loop {
            let n = stream
                .read(&mut read_buf)
                .await
                .map_err(|e| format!("Failed to read HandshakeInit: {}", e))?;
            if n == 0 {
                return Err("Connection closed before HandshakeInit".to_string());
            }
            decoder.feed(&read_buf[..n]);
            if let Some(frame) = decoder
                .decode_frame()
                .map_err(|e| format!("Decode error: {}", e))?
            {
                break frame;
            }
        };

        if init_frame.packet_type() != PacketType::HandshakeInit {
            return Err(format!(
                "Expected HandshakeInit packet, got {}",
                init_frame.packet_type()
            ));
        }

        let init_msg = HandshakeInit::from_bytes(init_frame.payload())
            .map_err(|e| format!("Invalid HandshakeInit payload: {}", e))?;

        if let Some(client_pk) = expected_client_sig_pk {
            if !init_msg.verify(client_pk) {
                return Err("Client HandshakeInit signature verification failed".to_string());
            }
        }

        // 2. Perform Hybrid KEM encapsulation & construct HandshakeResponse
        let (kem_ct, server_shared_secret) = encapsulate_hybrid(&init_msg.ephemeral_pk);
        let mut server_nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_nonce);

        let resp_msg = HandshakeResponse::create(
            kem_ct,
            server_nonce,
            &self.sig_keys.secret_key,
        );

        let resp_frame = resp_msg
            .to_frame(1)
            .map_err(|e| format!("Failed to frame HandshakeResponse: {}", e))?;
        stream
            .write_all(&resp_frame.encode())
            .await
            .map_err(|e| format!("Failed to write HandshakeResponse: {}", e))?;

        // 3. Derive AEAD session write keys
        let transcript = hash_transcript(&[&init_msg.to_bytes(), &resp_msg.to_bytes()]);
        let mut session_keys = derive_session_keys(&server_shared_secret, &transcript);

        let mut session = Session::new_server();
        session.set_rekey_threshold(self.config.rekey_threshold);
        session
            .establish(&session_keys)
            .map_err(|e| format!("Failed to establish server session: {}", e))?;

        info!("Server tunnel session established (id: {})", session.session_id());

        // 4. Data transfer and heartbeat loop
        loop {
            if let Some(frame) = decoder
                .decode_frame()
                .map_err(|e| format!("Decode error: {}", e))?
            {
                match frame.packet_type() {
                    PacketType::Data => {
                        let decrypted = session
                            .decrypt_packet(&frame)
                            .map_err(|e| format!("Decryption failed: {}", e))?;
                        debug!("Server received {} bytes payload", decrypted.len());

                        // Echo response with acknowledgement
                        let mut reply = Vec::from(b"ACK: ".as_slice());
                        reply.extend_from_slice(&decrypted);
                        let reply_frame = session
                            .encrypt_packet(PacketType::Data, &reply)
                            .map_err(|e| format!("Encryption failed: {}", e))?;
                        stream
                            .write_all(&reply_frame.encode())
                            .await
                            .map_err(|e| format!("Write failed: {}", e))?;
                    }
                    PacketType::Ping => {
                        let ping_ts = session
                            .handle_ping(&frame)
                            .map_err(|e| format!("Ping handling failed: {}", e))?;
                        let pong_frame = session
                            .create_pong(ping_ts)
                            .map_err(|e| format!("Pong creation failed: {}", e))?;
                        stream
                            .write_all(&pong_frame.encode())
                            .await
                            .map_err(|e| format!("Write pong failed: {}", e))?;
                    }
                    PacketType::Pong => {
                        let _ = session.decrypt_packet(&frame);
                    }
                    PacketType::HandshakeInit => {
                        session
                            .ratchet_rekey(&mut session_keys)
                            .map_err(|e| format!("Ratchet failed: {}", e))?;
                        let ack_frame = PacketFrame::new(
                            PacketType::HandshakeResp,
                            0,
                            b"RATCHET_ACK".to_vec(),
                        )?;
                        stream
                            .write_all(&ack_frame.encode())
                            .await
                            .map_err(|e| format!("Write ratchet ack failed: {}", e))?;
                    }
                    PacketType::HandshakeResp => {}
                }
                continue;
            }

            let n = match stream.read(&mut read_buf).await {
                Ok(0) => break, // Peer disconnected cleanly
                Ok(n) => n,
                Err(_) => break,
            };
            decoder.feed(&read_buf[..n]);
        }

        session.close();
        Ok(session.metrics().clone())
    }
}

/// Asynchronous Post-Quantum Hybrid Tunnel Client.
pub struct TunnelClient {
    pub sig_keys: HybridSigKeyPair,
    pub server_sig_pk: Option<HybridSigPublicKey>,
    pub config: TunnelConfig,
}

impl TunnelClient {
    pub fn new(sig_keys: HybridSigKeyPair, server_sig_pk: HybridSigPublicKey) -> Self {
        Self::with_config(sig_keys, Some(server_sig_pk), TunnelConfig::default())
    }

    pub fn new_trust_any(sig_keys: HybridSigKeyPair) -> Self {
        Self::with_config(sig_keys, None, TunnelConfig::default())
    }

    pub fn with_config(
        sig_keys: HybridSigKeyPair,
        server_sig_pk: Option<HybridSigPublicKey>,
        config: TunnelConfig,
    ) -> Self {
        Self {
            sig_keys,
            server_sig_pk,
            config,
        }
    }

    /// Connects to a remote server over TCP.
    pub async fn connect(
        &self,
        addr: &str,
    ) -> Result<EstablishedClientConnection<TcpStream>, String> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
        self.connect_stream(stream).await
    }

    /// Connects over an asynchronous bidirectional stream.
    pub async fn connect_stream<S>(
        &self,
        mut stream: S,
    ) -> Result<EstablishedClientConnection<S>, String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // 1. Generate ephemeral KEM and send HandshakeInit
        let ephemeral_kem = HybridKemKeyPair::generate();
        let mut client_nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut client_nonce);

        let init_msg = HandshakeInit::create(
            ephemeral_kem.public_key,
            client_nonce,
            &self.sig_keys.secret_key,
        );

        let init_frame = init_msg
            .to_frame(1)
            .map_err(|e| format!("Failed to frame HandshakeInit: {}", e))?;
        stream
            .write_all(&init_frame.encode())
            .await
            .map_err(|e| format!("Failed to write HandshakeInit: {}", e))?;

        // 2. Read HandshakeResponse
        let mut decoder = FrameDecoder::new();
        let mut read_buf = [0u8; 4096];

        let resp_frame = loop {
            let n = stream
                .read(&mut read_buf)
                .await
                .map_err(|e| format!("Failed to read HandshakeResponse: {}", e))?;
            if n == 0 {
                return Err("Connection closed before HandshakeResponse".to_string());
            }
            decoder.feed(&read_buf[..n]);
            if let Some(frame) = decoder
                .decode_frame()
                .map_err(|e| format!("Decode error: {}", e))?
            {
                break frame;
            }
        };

        if resp_frame.packet_type() != PacketType::HandshakeResp {
            return Err(format!(
                "Expected HandshakeResp packet, got {}",
                resp_frame.packet_type()
            ));
        }

        let resp_msg = HandshakeResponse::from_bytes(resp_frame.payload())
            .map_err(|e| format!("Invalid HandshakeResponse payload: {}", e))?;

        // 3. Verify server signature and decapsulate shared secret
        if let Some(ref server_pk) = self.server_sig_pk {
            if !resp_msg.verify(server_pk) {
                return Err("Server HandshakeResponse signature verification failed".to_string());
            }
        }

        let client_shared_secret =
            decapsulate_hybrid(&resp_msg.ciphertext, &ephemeral_kem.secret_key);

        // 4. Derive AEAD session write keys
        let transcript = hash_transcript(&[&init_msg.to_bytes(), &resp_msg.to_bytes()]);
        let session_keys = derive_session_keys(&client_shared_secret, &transcript);

        let mut session = Session::new_client();
        session.set_rekey_threshold(self.config.rekey_threshold);
        session
            .establish(&session_keys)
            .map_err(|e| format!("Failed to establish client session: {}", e))?;

        info!("Client tunnel session established (id: {})", session.session_id());

        Ok(EstablishedClientConnection {
            stream,
            session,
            session_keys,
            decoder,
        })
    }
}

/// Active established client connection ready for data and heartbeat transmission.
pub struct EstablishedClientConnection<S = TcpStream> {
    stream: S,
    session: Session,
    session_keys: SessionKeys,
    decoder: FrameDecoder,
}

impl<S> EstablishedClientConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn metrics(&self) -> &SessionMetrics {
        self.session.metrics()
    }

    /// Transmits an encrypted application data payload and awaits the server's reply.
    pub async fn send_data(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let frame = self
            .session
            .encrypt_packet(PacketType::Data, payload)
            .map_err(|e| format!("Data encryption failed: {}", e))?;

        self.stream
            .write_all(&frame.encode())
            .await
            .map_err(|e| format!("Failed to write data frame: {}", e))?;

        let mut read_buf = [0u8; 4096];
        loop {
            if let Some(resp_frame) = self
                .decoder
                .decode_frame()
                .map_err(|e| format!("Decode error: {}", e))?
            {
                if resp_frame.packet_type() != PacketType::Data {
                    return Err(format!(
                        "Expected Data reply, got {}",
                        resp_frame.packet_type()
                    ));
                }
                return self
                    .session
                    .decrypt_packet(&resp_frame)
                    .map_err(|e| format!("Decryption error: {}", e));
            }

            let n = self
                .stream
                .read(&mut read_buf)
                .await
                .map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                return Err("Connection closed while awaiting data reply".to_string());
            }
            self.decoder.feed(&read_buf[..n]);
        }
    }

    /// Transmits a keepalive ping frame and measures the network round-trip time (RTT).
    pub async fn ping(&mut self) -> Result<u64, String> {
        let now_ms = Instant::now().elapsed().as_millis() as u64;
        let ping_frame = self
            .session
            .create_ping(now_ms)
            .map_err(|e| format!("Ping creation failed: {}", e))?;

        self.stream
            .write_all(&ping_frame.encode())
            .await
            .map_err(|e| format!("Failed to send ping frame: {}", e))?;

        let mut read_buf = [0u8; 4096];
        loop {
            if let Some(resp_frame) = self
                .decoder
                .decode_frame()
                .map_err(|e| format!("Decode error: {}", e))?
            {
                if resp_frame.packet_type() != PacketType::Pong {
                    return Err(format!(
                        "Expected Pong packet, got {}",
                        resp_frame.packet_type()
                    ));
                }
                let current_time = Instant::now().elapsed().as_millis() as u64;
                return self
                    .session
                    .handle_pong(&resp_frame, current_time)
                    .map_err(|e| format!("Pong handle error: {}", e));
            }

            let n = self
                .stream
                .read(&mut read_buf)
                .await
                .map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                return Err("Connection closed while awaiting pong".to_string());
            }
            self.decoder.feed(&read_buf[..n]);
        }
    }

    /// Advances the symmetric ratchet on both client and server sessions for forward secrecy.
    pub async fn ratchet(&mut self) -> Result<(), String> {
        let frame = PacketFrame::new(PacketType::HandshakeInit, 0, b"RATCHET".to_vec())?;
        self.stream
            .write_all(&frame.encode())
            .await
            .map_err(|e| format!("Failed to send ratchet signal: {}", e))?;

        let mut read_buf = [0u8; 4096];
        loop {
            if let Some(resp_frame) = self
                .decoder
                .decode_frame()
                .map_err(|e| format!("Decode error: {}", e))?
            {
                if resp_frame.packet_type() != PacketType::HandshakeResp {
                    return Err(format!(
                        "Expected HandshakeResp ratchet ack, got {}",
                        resp_frame.packet_type()
                    ));
                }
                break;
            }
            let n = self
                .stream
                .read(&mut read_buf)
                .await
                .map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                return Err("Connection closed while awaiting ratchet ack".to_string());
            }
            self.decoder.feed(&read_buf[..n]);
        }

        self.session.ratchet_rekey(&mut self.session_keys)
    }

    /// Closes the client connection gracefully.
    pub async fn close(mut self) {
        self.session.close();
        let _ = self.stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_tunnel_roundtrip() {
        let server_sig = HybridSigKeyPair::generate();
        let server_sig_pk = server_sig.public_key.clone();
        let client_sig = HybridSigKeyPair::generate();

        let (client_io, server_io) = tokio::io::duplex(16384);

        let server = TunnelServer::new(server_sig);
        let client = TunnelClient::new(client_sig, server_sig_pk);

        // Spawn server handling stream
        let server_handle = tokio::spawn(async move {
            server.handle_stream(server_io, None).await.unwrap()
        });

        // Run client on stream
        let mut conn = client.connect_stream(client_io).await.expect("Client connect failed");

        // Send data
        let reply = conn.send_data(b"Hello Quantum Gateway").await.unwrap();
        assert_eq!(reply, b"ACK: Hello Quantum Gateway");

        // Send ping
        let rtt = conn.ping().await.unwrap();
        assert!(rtt < 1000);

        // Ratchet keys
        conn.ratchet().await.unwrap();

        let post_ratchet_reply = conn.send_data(b"Post Ratchet Message").await.unwrap();
        assert_eq!(post_ratchet_reply, b"ACK: Post Ratchet Message");

        conn.close().await;
        let server_metrics = server_handle.await.unwrap();
        assert!(server_metrics.tx_packets >= 3);
        assert!(server_metrics.rx_packets >= 3);
        assert_eq!(server_metrics.rekeys_completed, 1);
    }

    #[tokio::test]
    async fn test_tunnel_client_signature_verification_enforcement() {
        let server_sig = HybridSigKeyPair::generate();
        let expected_client_sig = HybridSigKeyPair::generate();
        let wrong_client_sig = HybridSigKeyPair::generate();

        let (client_io, server_io) = tokio::io::duplex(8192);

        let server = TunnelServer::new(server_sig);
        let client = TunnelClient::new(wrong_client_sig, server.sig_keys.public_key.clone());

        let server_handle = tokio::spawn(async move {
            server
                .handle_stream(server_io, Some(&expected_client_sig.public_key))
                .await
        });

        let client_res = client.connect_stream(client_io).await;
        let server_res = server_handle.await.unwrap();

        assert!(server_res.is_err());
        assert!(server_res
            .unwrap_err()
            .contains("Client HandshakeInit signature verification failed"));
        let _ = client_res;
    }

    #[tokio::test]
    async fn test_tunnel_server_signature_mismatch_rejected_by_client() {
        let server_sig = HybridSigKeyPair::generate();
        let impostor_server_pk = HybridSigKeyPair::generate().public_key;
        let client_sig = HybridSigKeyPair::generate();

        let (client_io, server_io) = tokio::io::duplex(8192);

        let server = TunnelServer::new(server_sig);
        // Client expects impostor_server_pk instead of actual server_sig
        let client = TunnelClient::new(client_sig, impostor_server_pk);

        tokio::spawn(async move {
            let _ = server.handle_stream(server_io, None).await;
        });

        let client_res = client.connect_stream(client_io).await;
        match client_res {
            Err(e) => assert!(e.contains("Server HandshakeResponse signature verification failed")),
            Ok(_) => panic!("Expected handshake failure due to signature mismatch"),
        }
    }

    #[test]
    fn test_tunnel_config_and_constructors() {
        let config = TunnelConfig::default();
        assert_eq!(config.rekey_threshold, 100_000);

        let sig1 = HybridSigKeyPair::generate();
        let sig2 = HybridSigKeyPair::generate();
        let custom_config = TunnelConfig { rekey_threshold: 42 };
        let server = TunnelServer::with_config(sig1, custom_config.clone());
        assert_eq!(server.config.rekey_threshold, 42);

        let client = TunnelClient::with_config(sig2, Some(server.sig_keys.public_key.clone()), custom_config);
        assert_eq!(client.config.rekey_threshold, 42);
    }
}
