use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn kdc_send_recv(dc: &str, req: &[u8]) -> Result<Vec<u8>> {
    let addr = format!("{}:88", dc);
    let mut s = TcpStream::connect(&addr)
        .map_err(|e| anyhow!("Cannot connect to KDC {}: {}", addr, e))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    s.write_all(&(req.len() as u32).to_be_bytes())?;
    s.write_all(req)?;
    s.flush()?;

    if crate::is_debug() { eprintln!("[+] sent {} bytes to {}", req.len() + 4, addr); }

    s.set_read_timeout(Some(Duration::from_millis(3000)))?;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);

    if crate::is_debug() { eprintln!("[+] received {} bytes raw: {:02X?}", raw.len(),
              &raw[..raw.len().min(32)]); }

    if raw.is_empty() {
        anyhow::bail!("KDC sent nothing");
    }

    if raw.len() >= 4 {
        let rlen = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if rlen > 0 && rlen <= 8 * 1024 * 1024 && rlen + 4 <= raw.len() {
            if crate::is_debug() { eprintln!("[+] interpreting as length-prefixed: rlen={}", rlen); }
            return Ok(raw[4..4 + rlen].to_vec());
        }
        if rlen == 0 && raw.len() > 4 {
            if crate::is_debug() { eprintln!("[+] rlen=0, using bytes after prefix ({})", raw.len() - 4); }
            return Ok(raw[4..].to_vec());
        }
    }

    if crate::is_debug() { eprintln!("[+] no valid length prefix, returning raw"); }
    Ok(raw)
}