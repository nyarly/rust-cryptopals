use super::xor::*;
/// # Examples
/// ```
/// # use cryptopals::set1::challenge5::repeating_key_xor;
/// # use cryptopals::byte_convert::hex2bytes;
///
/// assert_eq!(
///   repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE").unwrap(),
///   hex2bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
///   a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").map(|s| String::from_utf8(s).unwrap()).unwrap()
/// );
/// ```
pub fn repeating_key_xor(text: &str, key: &str) -> Option<String> {
  String::from_utf8(xor_iters(text.bytes(), key.bytes().cycle())).ok()
}
