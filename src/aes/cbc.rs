use std::iter;
use xor;
use result::Result;
use super::ecb;

pub fn decrypt(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>> {
  let mut prev = Vec::from(iv);
  let mut acc = vec![];

  for block in input.chunks(16) {
    let ecb_decrypt = try!(ecb::decrypt(key, block));
    let next: Vec<u8> = xor::xor_iters(prev, ecb_decrypt);
    acc.extend_from_slice(&next);
    prev = Vec::from(block);
  }
  Ok(acc)
}

pub fn encrypt(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>> {
  let mut prev = Vec::from(iv);
  let mut acc = vec![];

  for block in input.chunks(16) {
    let mixed: Vec<u8> = xor::xor_iters(prev.to_vec(), block.to_vec());
    let next = try!(ecb::encrypt(key, &mixed));
    acc.extend_from_slice(&next);
    prev = Vec::from(next);
  }
  Ok(acc)
}

#[cfg(test)]
mod test {
  use super::*;
  #[test]
  fn encrypt_decrypt() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = &[0; 16][..];
    let message = "Attack the castle gates from the high west wall.".as_bytes();
    let crypted = encrypt(key, iv, message).unwrap();
    println!("");
    println!("{} {:?}", message.len(), message);
    println!("{} {:?}", crypted.len(), crypted);
    assert_eq!(message, decrypt(key, iv, &crypted).unwrap().as_slice())
  }
}
