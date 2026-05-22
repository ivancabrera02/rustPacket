use hmac::{Hmac, Mac};
use md5::Md5;

pub struct Key {
    pub etype: i32,
    pub key: Vec<u8>,
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac::<Md5> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub const KU_TGS_AUTH: u32 = 7;