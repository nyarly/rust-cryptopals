use crypto::{aes, blockmodes, buffer};
use std::iter;
use result::*;

pub fn decrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
  let mut out: Vec<u8> = iter::repeat(0u8).take(input.len()).collect();
  let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);

  {
    let mut cbuf = buffer::RefReadBuffer::new(input);
    let mut pbuf = buffer::RefWriteBuffer::new(out.as_mut_slice());
    try!(decryptor.decrypt(&mut cbuf, &mut pbuf, true));
  }
  Ok(out.clone())
}

pub fn encrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
  let mut out: Vec<u8> = iter::repeat(0u8).take(input.len()).collect();
  let mut encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);

  {
    let mut cbuf = buffer::RefReadBuffer::new(input);
    let mut pbuf = buffer::RefWriteBuffer::new(out.as_mut_slice());
    try!(encryptor.encrypt(&mut cbuf, &mut pbuf, true));
  }
  Ok(out.clone())
}

#[cfg(test)]
mod test {
  use super::*;
  #[test]
  fn encrypt_decrypt() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let message = "Attack the castle gates from the high west wall.".as_bytes();
    let crypted = encrypt(key, message).unwrap();
    println!("");
    println!("{} {:?}", message.len(), message);
    println!("{} {:?}", crypted.len(), crypted);
    assert_eq!(message, decrypt(key, &crypted).unwrap().as_slice())
  }
}
