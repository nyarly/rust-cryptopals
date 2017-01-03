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
