use serialize::base64::FromBase64;
use result::{Result, CrackError};

use aes::ecb;
use random;
use padding;

/// Byte-at-a-time ECB decryption (Simple)
/// Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
///
/// Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
///
/// Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
/// aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
/// dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
/// YnkK
///
/// Spoiler alert.
/// Do not decode this string now. Don't do it.
///
/// Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.
///
/// What you have now is a function that produces:
///
/// AES-128-ECB(your-string || unknown-string, random-key)
/// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
///
/// Here's roughly how:
///
/// Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
/// Detect that the function is using ECB. You already know, but do this step anyways.
/// Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
/// Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
/// Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
/// Repeat for the next byte.
///
#[cfg(test)]
mod test {
  #[test]
  fn can_solve() {
    let cracked = super::solve("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes());

    assert!(cracked.find("waving just").is_some())
  }
}

pub fn solve(b64msg: &[u8]) -> String {
  let oracle = EncryptionOracle::new(b64msg);
  let mut supplicant = Supplicant::new(&oracle);
  supplicant.interrogate().unwrap();
  String::from_utf8(supplicant.decrypted).unwrap()
}

struct EncryptionOracle {
  key: Vec<u8>,
  message: Vec<u8>,
}

impl EncryptionOracle {
  fn new(msg: &[u8]) -> EncryptionOracle {
    let b64msg = msg.clone();
    let msg = b64msg.from_base64().unwrap();
    EncryptionOracle {
      key: random::bytes(16),
      message: msg,
    }
  }

  pub fn advise(&self, input: &[u8]) -> Result<Vec<u8>> {
    ecb::encrypt(&self.key,
                 &padding::pkcs7(&[input, &self.message].concat(), 16))
  }
}

struct Supplicant<'g> {
  block_size: usize,
  cipher_mode: Mode,
  target_crypt: Vec<u8>,
  target_size: usize,
  decrypted: Vec<u8>,
  oracle: &'g EncryptionOracle,
}

use std::iter::{once, repeat};
use utils::full_u8;
use analysis::{self, Mode};

impl<'g> Supplicant<'g> {
  fn new(oracle: &EncryptionOracle) -> Supplicant {
    Supplicant {
      block_size: 16,
      cipher_mode: Mode::CipherBlockChaining,
      target_crypt: vec![],
      target_size: 0,
      decrypted: vec![],
      oracle: oracle,
    }
  }

  fn interrogate(&mut self) -> Result<&Supplicant> {
    let (bs, ts) = try!(self.block_period());
    self.block_size = bs;
    self.target_size = ts;
    self.cipher_mode = try!(self.detect_mode());
    self.target_crypt = try!(self.oracle.advise(&[][0..0]));
    for _ in 0..self.target_size {
      let next_byte = try!(self.build_dict(&self.decrypted));
      self.decrypted.push(next_byte)
    }
    println!("Validation!");
    self.validate()
  }

  fn validate(&self) -> Result<&Supplicant> {
    let trial = &padding::pkcs7(&self.decrypted, self.block_size);
    let prophecy = &try!(self.oracle.advise(trial));
    let check = &prophecy[0..self.target_crypt.len()];
    let against = &self.target_crypt[..];

    if check == against {
      Ok(self)
    } else {
      Err(CrackError::Str("Doesn't match!"))
    }
  }

  fn build_dict(&self, known: &[u8]) -> Result<u8> {
    let target_block_start = (known.len() / self.block_size) * self.block_size;
    let target_block_end = target_block_start + self.block_size;
    let target_block_range = target_block_start..target_block_end;
    let target_known_bytes = known.len() - target_block_start;
    let a = &b'a';
    let shim = repeat(a).take(self.block_size - target_known_bytes - 1);

    let msg: Vec<u8> = shim.clone().cloned().collect();
    let target = &try!(self.oracle.advise(&msg))[target_block_range.clone()];

    for c in full_u8() {
      let trial: Vec<u8> = shim.clone().chain(known).cloned().chain(once(c)).collect();
      let prophecy = &try!(self.oracle.advise(&trial))[target_block_range.clone()];

      if prophecy == target {
        return Ok(c);
      }
    }
    return Err(CrackError::Str("No byte satisfies!"));
  }

  fn block_period(&self) -> Result<(usize, usize)> {
    let base_size = try!(self.oracle.advise(&[][0..0])).len();
    for n in 1..64 {
      let size = try!(self.oracle.advise(&(repeat(b'a').take(n).collect::<Vec<_>>()))).len();
      if size != base_size {
        println!("{} {} {}", base_size, size, n);
        println!("{} {}", size - base_size, base_size - n);

        return Ok((size - base_size, base_size - n));
      }
    }
    Err(CrackError::Str("No block periodicity detected"))
  }

  fn detect_mode(&self) -> Result<Mode> {
    let oracle_fn = |msg: &[u8]| self.oracle.advise(msg);
    analysis::aes::detector(self.block_size, oracle_fn)
  }
}
