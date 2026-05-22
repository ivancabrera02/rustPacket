pub fn encode_length(len: usize) -> Vec<u8> {
    if len <= 0x7F { vec![len as u8] }
    else if len <= 0xFF { vec![0x81, len as u8] }
    else if len <= 0xFFFF { vec![0x82, (len>>8) as u8, (len&0xFF) as u8] }
    else { vec![0x84,(len>>24) as u8,(len>>16) as u8,(len>>8) as u8,(len&0xFF) as u8] }
}
pub fn decode_length(data: &[u8], offset: &mut usize) -> anyhow::Result<usize> {
    if *offset >= data.len() { anyhow::bail!("ASN1: EOF at length"); }
    let first = data[*offset] as usize; *offset += 1;
    if first & 0x80 == 0 { return Ok(first); }
    let nb = first & 0x7F;
    if *offset + nb > data.len() { anyhow::bail!("ASN1: truncated length"); }
    let mut len = 0usize;
    for _ in 0..nb { len = (len<<8) | data[*offset] as usize; *offset += 1; }
    Ok(len)
}
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut o = vec![tag]; o.extend(encode_length(value.len())); o.extend_from_slice(value); o
}
pub fn ctx(n: u8, inner: &[u8]) -> Vec<u8> { tlv(0xA0|n, inner) }
pub fn app(n: u8, inner: &[u8]) -> Vec<u8> { tlv(0x60|n, inner) }
pub fn seq(inner: &[u8]) -> Vec<u8> { tlv(0x30, inner) }
pub fn seq_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut b=Vec::new(); for i in items { b.extend_from_slice(i); } tlv(0x30,&b)
}
pub fn int(v: i64) -> Vec<u8> {
    if v==0 { return tlv(0x02,&[0x00]); }
    let mut bytes = v.to_be_bytes().to_vec();
    if v>0 {
        while bytes.len()>1 && bytes[0]==0x00 && bytes[1]&0x80==0 { bytes.remove(0); }
        if bytes[0]&0x80!=0 { bytes.insert(0,0x00); }
    } else {
        while bytes.len()>1 && bytes[0]==0xFF && bytes[1]&0x80!=0 { bytes.remove(0); }
    }
    tlv(0x02,&bytes)
}
pub fn ostr(data: &[u8]) -> Vec<u8> { tlv(0x04, data) }
pub fn gstr(s: &str) -> Vec<u8> { tlv(0x1B, s.as_bytes()) }
pub fn gentime(t: &str) -> Vec<u8> { tlv(0x18, t.as_bytes()) }
pub fn bitstr(data: &[u8], unused: u8) -> Vec<u8> {
    let mut v=vec![unused]; v.extend_from_slice(data); tlv(0x03,&v)
}
pub fn enc_data(etype: i32, kvno: Option<u32>, cipher: &[u8]) -> Vec<u8> {
    let mut b = ctx(0,&int(etype as i64));
    if let Some(k)=kvno { b.extend(ctx(1,&int(k as i64))); }
    b.extend(ctx(2,&ostr(cipher)));
    seq(&b)
}
pub fn principal_name(name_type: i32, parts: &[&str]) -> Vec<u8> {
    let mut b = ctx(0,&int(name_type as i64));
    let strs: Vec<Vec<u8>> = parts.iter().map(|s| gstr(s)).collect();
    b.extend(ctx(1,&seq_of(&strs)));
    seq(&b)
}

pub struct Reader<'a> { pub d: &'a [u8], pub p: usize }
impl<'a> Reader<'a> {
    pub fn new(d: &'a [u8]) -> Self { Reader{d,p:0} }
    pub fn done(&self) -> bool { self.p >= self.d.len() }
    pub fn peek(&self) -> Option<u8> { self.d.get(self.p).copied() }
    pub fn tlv(&mut self) -> anyhow::Result<(u8,&'a [u8])> {
        if self.p >= self.d.len() { anyhow::bail!("DER: EOF"); }
        let tag=self.d[self.p]; self.p+=1;
        let len=decode_length(self.d, &mut self.p)?;
        if self.p+len>self.d.len() { anyhow::bail!("DER: truncated value"); }
        let v=&self.d[self.p..self.p+len]; self.p+=len;
        Ok((tag,v))
    }
    pub fn ctx(&mut self, n: u8) -> anyhow::Result<&'a [u8]> {
        let exp=0xA0|n; let (t,v)=self.tlv()?;
        if t!=exp { anyhow::bail!("DER: expected ctx[{}]=0x{:02X}, got 0x{:02X}",n,exp,t); }
        Ok(v)
    }
    pub fn read_int(&mut self) -> anyhow::Result<i64> {
        let (t,v)=self.tlv()?;
        if t!=0x02 { anyhow::bail!("DER: not INTEGER 0x{:02X}",t); }
        if v.is_empty() { anyhow::bail!("DER: empty INTEGER"); }
        let neg=v[0]&0x80!=0;
        let mut r:i64=if neg{-1}else{0};
        for &b in v { r=(r<<8)|(b as i64); }
        Ok(r)
    }
    pub fn read_ostr(&mut self) -> anyhow::Result<&'a [u8]> {
        let (t,v)=self.tlv()?;
        if t!=0x04 { anyhow::bail!("DER: not OCTET STRING 0x{:02X}",t); }
        Ok(v)
    }
    pub fn read_gstr(&mut self) -> anyhow::Result<String> {
        let (t,v)=self.tlv()?;
        if t!=0x1B { anyhow::bail!("DER: not GeneralString 0x{:02X}",t); }
        Ok(String::from_utf8_lossy(v).to_string())
    }

}
pub fn unwrap_app(data: &[u8], n: u8) -> anyhow::Result<&[u8]> {
    if data.is_empty() { anyhow::bail!("empty"); }
    let exp=0x60|n;
    if data[0]!=exp { anyhow::bail!("Expected APP[{}]=0x{:02X}, got 0x{:02X}",n,exp,data[0]); }
    let mut p=1usize;
    let len=decode_length(data,&mut p)?;
    if p+len>data.len() { anyhow::bail!("APP tag truncated"); }
    Ok(&data[p..p+len])
}
pub fn parse_enc_data(data: &[u8]) -> anyhow::Result<(i32,Vec<u8>)> {
    let mut r=Reader::new(data); let(_,sd)=r.tlv()?; let mut s=Reader::new(sd);
    let et=Reader::new(s.ctx(0)?).read_int()? as i32;
    if s.peek()==Some(0xA1) { let _=s.ctx(1)?; }
    let ci=Reader::new(s.ctx(2)?).read_ostr()?.to_vec();
    Ok((et,ci))
}

pub fn decode_length_pair(data: &[u8], offset: usize) -> anyhow::Result<(usize, usize)> {
    let mut p = offset;
    let l = decode_length(data, &mut p)?;
    Ok((l, p))
}