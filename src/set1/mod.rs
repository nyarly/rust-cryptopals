pub mod challenge1;
// pub mod challenge2;
// pub mod challenge3;
pub mod challenge4;
pub mod challenge5;
pub mod challenge6;
pub mod challenge7;
pub mod challenge8;

/// The hex encoded string:
///
/// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// # Examples
///
/// ```
/// # use cryptopals::set1::best_hex_decrypt;
///
/// let best = best_hex_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
/// assert_eq!(
///   String::from_utf8(best).unwrap(),
///   "Cooking MC's like a pound of bacon"
/// )
/// ```
use ::byte_convert::*;
use xor;
use utils;

pub fn best_hex_decrypt(encrypted: &str) -> Vec<u8> {
  let cstr = hex2bytes(encrypted).unwrap();

  best_decrypt(&cstr)
}

pub fn best_decrypt(cstr: &[u8]) -> Vec<u8> {
  let (_, best) = utils::best_score(utils::full_u8().map(|c| xor::scored_decrypt(&cstr, c)))
                    .unwrap_or_else(|| (0, xor::decrypt(&cstr, b'0')));
  best
}
