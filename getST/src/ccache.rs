use anyhow::Result;
use std::io::Write;
use std::fs::File;
use crate::krb5::Ticket2 as Ticket;

pub fn write_ccache(path: &str, t: &Ticket, realm: &str, client: &str) -> Result<()> {
    let mut f = File::create(path)?;
    f.write_all(&0x0504u16.to_be_bytes())?;
    let hdr: &[u8] = &[0x00,0x01, 0x00,0x08, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00];
    f.write_all(&(hdr.len() as u16).to_be_bytes())?;
    f.write_all(hdr)?;
    write_principal(&mut f, realm, client, 1)?;
    write_credential(&mut f, t, realm, client)?;
    Ok(())
}

fn wcs(f: &mut File, s: &str) -> Result<()> {
    let b = s.as_bytes();
    f.write_all(&(b.len() as u32).to_be_bytes())?;
    f.write_all(b)?; Ok(())
}

fn write_principal(f: &mut File, realm: &str, name: &str, name_type: u32) -> Result<()> {
    let parts: Vec<&str> = name.split('/').collect();
    f.write_all(&name_type.to_be_bytes())?;
    f.write_all(&(parts.len() as u32).to_be_bytes())?;
    wcs(f, realm)?;
    for p in &parts { wcs(f, p)?; }
    Ok(())
}

fn write_credential(f: &mut File, t: &Ticket, realm: &str, client: &str) -> Result<()> {
    write_principal(f, realm, client, 1)?;
    let srealm = t.server_realm.as_deref().unwrap_or(realm);
    let snt: u32 = if t.service.contains('/') { 2 } else { 1 };
    let svc_lower = t.service.to_lowercase();
    write_principal(f, srealm, &svc_lower, snt)?;
    f.write_all(&(t.session_etype as u16).to_be_bytes())?;
    f.write_all(&(t.session_key.len() as u32).to_be_bytes())?;
    f.write_all(&t.session_key)?;
    f.write_all(&t.auth_time.to_be_bytes())?;
    f.write_all(&t.start_time.to_be_bytes())?;
    f.write_all(&t.end_time.to_be_bytes())?;
    f.write_all(&t.renew_till.to_be_bytes())?;
    f.write_all(&[0u8])?;
    f.write_all(&t.flags.to_be_bytes())?;
    f.write_all(&0u32.to_be_bytes())?;
    f.write_all(&0u32.to_be_bytes())?;
    f.write_all(&(t.ticket_data.len() as u32).to_be_bytes())?;
    f.write_all(&t.ticket_data)?;
    f.write_all(&0u32.to_be_bytes())?;
    Ok(())
}

pub fn read_ccache(path: &str) -> Result<(Vec<u8>, Vec<u8>, i32)> {
    let data = std::fs::read(path)?;
    if data.len() < 4 { anyhow::bail!("ccache too short"); }
    let ver = u16::from_be_bytes([data[0],data[1]]);
    if ver != 0x0504 { anyhow::bail!("Unsupported ccache version 0x{:04X}", ver); }
    let hlen = u16::from_be_bytes([data[2],data[3]]) as usize;
    let mut pos = 4 + hlen;
    pos = skip_principal(&data, pos)?;
    pos = skip_principal(&data, pos)?;
    pos = skip_principal(&data, pos)?;
    if pos+4 > data.len() { anyhow::bail!("ccache: truncated keyblock"); }
    let etype = i16::from_be_bytes([data[pos],data[pos+1]]) as i32; pos+=2;
    let klen = u16::from_be_bytes([data[pos],data[pos+1]]) as usize; pos+=2;
    let sk = data[pos..pos+klen].to_vec(); pos += klen;
    pos += 16; pos += 1; pos += 4;
    if pos+4>data.len() { anyhow::bail!("ccache: no addr count"); }
    let ac = u32::from_be_bytes(data[pos..pos+4].try_into()?) as usize; pos+=4;
    for _ in 0..ac {
        pos+=2;
        if pos+4>data.len() { anyhow::bail!("ccache: addr truncated"); }
        let al = u32::from_be_bytes(data[pos..pos+4].try_into()?) as usize; pos+=4+al;
    }
    if pos+4>data.len() { anyhow::bail!("ccache: no auth count"); }
    let authc = u32::from_be_bytes(data[pos..pos+4].try_into()?) as usize; pos+=4;
    for _ in 0..authc {
        pos+=2;
        if pos+4>data.len() { anyhow::bail!("ccache: authdata truncated"); }
        let al = u32::from_be_bytes(data[pos..pos+4].try_into()?) as usize; pos+=4+al;
    }
    if pos+4>data.len() { anyhow::bail!("ccache: no ticket len"); }
    let tlen = u32::from_be_bytes(data[pos..pos+4].try_into()?) as usize; pos+=4;
    let td = data[pos..pos+tlen].to_vec();
    Ok((td, sk, etype))
}

fn skip_principal(data: &[u8], mut p: usize) -> Result<usize> {
    if p+8>data.len() { anyhow::bail!("ccache: skip_principal EOF"); }
    p+=4;
    let nc = u32::from_be_bytes(data[p..p+4].try_into()?) as usize; p+=4;
    if p+4>data.len() { anyhow::bail!("ccache: realm len EOF"); }
    let rl = u32::from_be_bytes(data[p..p+4].try_into()?) as usize; p+=4+rl;
    for _ in 0..nc {
        if p+4>data.len() { anyhow::bail!("ccache: comp len EOF"); }
        let cl = u32::from_be_bytes(data[p..p+4].try_into()?) as usize; p+=4+cl;
    }
    Ok(p)
}