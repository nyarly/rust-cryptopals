use super::super::byte_convert;
use super::super::result::Result;
use super::frequency;

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
/// assert_eq!(
///   cryptopal::set1::challenge8::detect_aes_ecb("./s1c8.txt").unwrap().unwrap(),
///   "zxcv"
///   )
/// ```
pub fn detect_aes_ecb(path: &str) -> Result<Option<Vec<u8>>> {
    let crypts = try!(byte_convert::open_hexlines_path(path));

    for crypt in crypts {
        let chunks = (&crypt).chunks(16).map(|ch| &String::from_utf8_lossy(ch)).collect::<Vec<_>>();
        let c = frequency::Counts::new(chunks);
        if c.sorted_counts()[0] > 1 {
            return Ok(Some(crypt));
        }
    }
    return Ok(None);
}
