use super::super::byte_convert;
use super::super::result::Result;
use frequency;
use num_bigint::{BigInt, Sign};

/// Detect AES in ECB mode
/// In this file are a bunch of hex-encoded ciphertexts.
///
/// One of them has been encrypted with ECB.
///
/// Detect it.
///
/// Remember that the problem with ECB is that it is stateless and
/// deterministic; the same 16 byte plaintext block will always produce the
/// same 16 byte ciphertext.
///
/// Examples
///
/// ```
/// cryptopals::set1::challenge8::detect_aes_ecb("./s1c8.txt").unwrap().unwrap();
/// ```
pub fn detect_aes_ecb(path: &str) -> Result<Option<Vec<u8>>> {
  let crypts = try!(byte_convert::open_hexlines_path(path));

  for crypt in crypts {
    let chunks = (&crypt).chunks(16).map(|ch| BigInt::from_bytes_be(Sign::Plus, ch));
    let c = frequency::Counts::new(chunks);
    if c.sorted_counts()[0] > 1 {
      return Ok(Some(crypt.clone()));
    }
  }
  return Ok(None);
}
