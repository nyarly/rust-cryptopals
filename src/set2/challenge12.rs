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
    assert!(super::solve()
      .find("Supercalafragilisticexpialidocious")
      .is_some())
  }
}

pub fn solve() -> String {
  let oracle = EncryptionOracle::new();
  let mut supplicant = Supplicant::new(&oracle);
  supplicant.interrogate().unwrap();
  String::from_utf8(supplicant.decrypted).unwrap()
}

struct EncryptionOracle {
  key: Vec<u8>,
  message: Vec<u8>,
}

impl EncryptionOracle {
  fn new() -> EncryptionOracle {
    let b64msg = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes();
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
      target_size: 0,
      decrypted: vec![],
      oracle: oracle,
    }
  }

  fn interrogate(&mut self) -> Result<&Supplicant> {
    self.block_size = try!(self.block_period());
    self.target_size = try!(self.oracle.advise(&[][0..0])).len();
    for _ in 0..self.target_size {
      let next_byte = try!(self.build_dict(&self.decrypted));
      self.decrypted.push(next_byte)
    }
    Ok(self)
  }


  fn build_dict(&self, known: &[u8]) -> Result<u8> {
    let prefix_length = (known.len() % self.block_size) * self.block_size;
    let suffix_length = known.len() - prefix_length;
    let a = &b'a';
    println!("{} {} {}", prefix_length, suffix_length, self.block_size);
    let shim = known[..prefix_length]
      .iter()
      .chain(repeat(a).take(self.block_size - suffix_length - 1))
      .chain(&known[prefix_length..]);

    let msg: Vec<u8> = shim.clone().cloned().collect();
    let target = try!(self.oracle.advise(&msg));

    for c in full_u8() {
      let trial: Vec<u8> = shim.clone().cloned().chain(once(c)).collect();
      let prophecy = try!(self.oracle.advise(&trial));

      if prophecy[prefix_length..known.len()] == target[prefix_length..known.len()] {
        return Ok(c);
      }
    }
    return Err(CrackError::Str("No byte satisfied prophecy!"));
  }

  fn block_period(&self) -> Result<usize> {
    for n in 1..64 {
      let oracle_fn = |msg: &[u8]| self.oracle.advise(msg);
      match try!(analysis::aes::detector(n, oracle_fn)) {
        Mode::ElectronicCodebook => return Ok(n),
        _ => (),
      }
    }
    Err(CrackError::Str("No block periodicity detected"))
  }
}
