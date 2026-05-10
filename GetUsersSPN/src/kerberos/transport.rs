//! TCP transport for Kerberos (port 88, RFC 4120 §7.2.2).
//! Length prefix: 4-byte big-endian signed int (matches Impacket struct.pack('!i',...))

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::KrbError;

pub struct KdcTransport {
    stream: TcpStream,
}

impl KdcTransport {
    pub async fn connect(host: &str, port: u16) -> Result<Self, KrbError> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| KrbError::Network(format!("connect {}: {}", addr, e)))?;
        Ok(Self { stream })
    }

    /// Send a Kerberos message with 4-byte big-endian length prefix (like Impacket's sendall).
    pub async fn send(&mut self, msg: &[u8]) -> Result<(), KrbError> {
        let len = (msg.len() as u32).to_be_bytes();
        // Send length + message in a single write (matches Impacket's s.sendall(len + data))
        let mut buf = Vec::with_capacity(4 + msg.len());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(msg);
        self.stream.write_all(&buf).await
            .map_err(|e| KrbError::Network(e.to_string()))
    }

    /// Receive one Kerberos message.
    pub async fn recv(&mut self) -> Result<Vec<u8>, KrbError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await
            .map_err(|e| KrbError::Network(format!("read length: {}", e)))?;

        let len = u32::from_be_bytes(len_buf) as usize;

        if len == 0 {
            return Err(KrbError::Network(format!(
                "KDC returned zero-length response (raw length bytes: {:02x} {:02x} {:02x} {:02x})",
                len_buf[0], len_buf[1], len_buf[2], len_buf[3]
            )));
        }
        if len > 64 * 1024 * 1024 {
            return Err(KrbError::Network(format!(
                "KDC response too large: {} bytes (raw: {:02x}{:02x}{:02x}{:02x})",
                len, len_buf[0], len_buf[1], len_buf[2], len_buf[3]
            )));
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await
            .map_err(|e| KrbError::Network(format!("read payload ({} bytes): {}", len, e)))?;
        Ok(buf)
    }
}
