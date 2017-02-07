use aes::{ecb, cbc};
use result::Result;
use num_bigint::{BigInt, Sign};
use rand::{self, Rng};

use frequency;
use padding;
use random;


/// An ECB/CBC detection oracle
/// Now that you have ECB and CBC working:
///
/// Write a function to generate a random AES key; that's just 16 random bytes.
///
/// Write a function that encrypts data under an unknown key --- that is, a
/// function that generates a random key and encrypts under it.
///
/// The function should look like:
///
/// encryption_oracle(your-input)
/// => [MEANINGLESS JIBBER JABBER]
///
/// Under the hood, have the function append 5-10 bytes (count chosen randomly)
/// before the plaintext and 5-10 bytes after the plaintext.
///
/// Now, have the function choose to encrypt under ECB 1/2 the time, and under
/// CBC the other half (just use random IVs each time for CBC). Use rand(2) to
/// decide which to use.
///
/// Detect the block cipher mode the function is using each time. You should end
/// up with a piece of code that, pointed at a block box that might be
/// encrypting ECB or CBC, tells you which one is happening.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Mode {
  ElectronicCodebook,
  CipherBlockChaining,
}

pub fn detector(oracle: fn(&[u8]) -> Result<Vec<u8>>) -> Result<Mode> {
  let exploit_message = &[0; 96]; // 6 * 16 = blocksize (should work down to 3)

  let crypt = try!(oracle(exploit_message));
  let chunks = (&crypt.as_slice()).chunks(16).map(|ch| BigInt::from_bytes_be(Sign::Plus, ch));
  let c = frequency::Counts::new(chunks);

  if c.sorted_counts()[0] > 1 {
    Ok(Mode::ElectronicCodebook)
  } else {
    Ok(Mode::CipherBlockChaining)
  }
}

pub fn encryption_oracle(input: &[u8]) -> Result<Vec<u8>> {
  let mut rng = rand::thread_rng();

  let oracle = if rng.gen() {
    pick_encryption_oracle(Mode::ElectronicCodebook)
  } else {
    pick_encryption_oracle(Mode::CipherBlockChaining)
  };

  oracle(input)
}

fn pick_encryption_oracle(kind: Mode) -> fn(&[u8]) -> Result<Vec<u8>> {
  match kind {
    Mode::ElectronicCodebook => ecb_encryption_oracle,
    Mode::CipherBlockChaining => cbc_encryption_oracle,
  }
}

fn cbc_encryption_oracle(your_input: &[u8]) -> Result<Vec<u8>> {
  cbc::encrypt(&random::bytes(16),
               &random::bytes(16),
               &padding::pkcs7(&random::padding(your_input), 16))
}

fn ecb_encryption_oracle(your_input: &[u8]) -> Result<Vec<u8>> {
  ecb::encrypt(&random::bytes(16),
               &padding::pkcs7(&random::padding(your_input), 16))
}

#[cfg(test)]
mod test {
  use super::{Mode, detector, pick_encryption_oracle};

  fn matching_mode(mode: Mode) {
    assert_eq!(detector(pick_encryption_oracle(mode)).unwrap(), mode);
  }

  #[test]
  fn recognize_ecb() {
    matching_mode(Mode::ElectronicCodebook)
  }

  #[test]
  fn recognize_cbc() {
    matching_mode(Mode::CipherBlockChaining)
  }
}
