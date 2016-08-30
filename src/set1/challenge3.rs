///The hex encoded string:
///
///1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
///... has been XOR'd against a single character. Find the key, decrypt the message.
///
///You can do this by hand. But don't: write code to do it for you.
///
/// # Examples
///
/// ```
/// # use cryptopals::set1::challenge3::best_decrypt;
///
/// let best = best_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
/// assert_eq!(
///   String::from_utf8(best).unwrap(),
///   "Cooking MC's like a pound of bacon"
/// )
/// ```
use super::utils::*;
pub fn best_decrypt(encrypted: &str) -> Vec<u8> {
  let cstr = hex2bytes(encrypted).unwrap();

  let (_, best) = best_score(full_u8().map(|c| scored_decrypt(&cstr, c)))
    .unwrap_or_else(|| (0, decrypt(&cstr, b'0')));
  best
}
