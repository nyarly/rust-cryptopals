use byte_convert::open_base64_path;
use result::*;
use aes::ecb;

/// Examples
///
/// ```
/// let decrypt = cryptopals::set1::challenge7::decrypt_file("s1c7.txt").unwrap();
/// assert!( decrypt.find("Samson to Delilah").is_some())
/// ```
pub fn decrypt_file(path: &str) -> Result<String> {
  let crypted = try!(open_base64_path(path));

  let plain = try!(ecb::decrypt("YELLOW SUBMARINE".as_bytes(), &crypted));

  String::from_utf8(plain).map_err(CrackError::from)
}
