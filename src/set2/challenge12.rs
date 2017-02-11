use serialize::base64::FromBase64;
use result::{Result, CrackError};

use aes::ecb;
use random;
use padding;

// Byte-at-a-time ECB decryption (Simple)
// Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
//
// Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
//
// Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
// aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
// dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
// YnkK
//
// Spoiler alert.
// Do not decode this string now. Don't do it.
//
// Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.
//
// What you have now is a function that produces:
//
// AES-128-ECB(your-string || unknown-string, random-key)
// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
//
// Here's roughly how:
//
// Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
// Detect that the function is using ECB. You already know, but do this step anyways.
// Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
// Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
// Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
// Repeat for the next byte.

pub fn solve() -> &'static str {
  let oracle = EncryptionOracle::new();
  let mut supplicant = Supplicant::new(&oracle);
  supplicant.interrogate().unwrap();
  "DONE"
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
    ecb::encrypt(&self.key, &padding::pkcs7(&[input, &self.message].concat()))
  }
}

struct Supplicant<'g> {
  block_size: usize,
  oracle: &'g EncryptionOracle,
}

use std::iter::repeat;
use util::full_u8;

impl<'g> Supplicant<'g> {
  fn new(oracle: &EncryptionOracle) -> Supplicant {
    Supplicant {
      block_size: 16,
      oracle: oracle,
    }
  }

  fn interrogate(&mut self) -> Result<&Supplicant> {
    // cheating: assuming ECB with 16 byte block
    // ( might be able to do block + ECB detection by sending 3 * speculated
    // blocksize, and looking for blocksize repeats...)
    //
    // let phase = try!(self.block_period(0));
    // self.block_size = try!(self.block_period(phase));
    let dictionary = self.build_dict("");
    Ok(self)
  }


  fn build_dict(&self, known: &[u8]) -> Result<u8> {
    let shim = repeat(b'a').take(block_size - 1);

    let target = self.oracle.advise(shim);

    for c in full_u8() {
      let trial = shim.chain(c).collect();
      let prophecy = &self.oracle.advise(trial);

      dict.insert(prophecy, trial)
    }
    return dict;
  }

  fn block_period(&self, block_phase: usize) -> Result<usize> {
    for n in 1..64 {
      let trial: Vec<u8> = repeat(b'A').take(n + block_phase).collect();
      match self.oracle.advise(&trial) {
        Err(_) => (),
        Ok(_) => return Ok(n),
      }
    }
    Err(CrackError::Str("No block periodicity detected"))
  }
}
