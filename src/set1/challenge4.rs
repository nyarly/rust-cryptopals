use std::fs::File;
use std::io::{BufRead,BufReader};
use super::utils::*;
use ::byte_convert::*;
/// One of the 60-character strings in this file has been encrypted by single-character XOR.
/// Observe:
///
/// # Examples
/// ```
/// # use cryptopals::set1::challenge4::detect_xor;
/// assert_eq!(
///   detect_xor("s3c4-data.txt").unwrap(),
///   "Now that the party is jumping\n"
/// )
/// ```
pub fn detect_xor(path: &str) -> Option<String> {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    let scored_lines = fr.lines()
               .filter_map(|l| l.ok())
               .filter_map(|l| hex2bytes(&l).ok())
               .flat_map(|line| {
                 full_u8().map(move |c| {
                   let sd = scored_decrypt(&line, c); sd
                 })
               });
    best_score(scored_lines).and_then(|(_, best)| {
      String::from_utf8(best).ok()
    })
  })
}
