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

use super::best_decrypt;
use super::frequency::isomorph_score;
use super::frequency::most_frequent;
use super::xor::scored_decrypt;

pub fn detect_xor(path: &str) -> Option<String> {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    let scored_lines = fr.lines()
               .filter_map(|l| l.ok())
               .filter_map(|l| hex2bytes(&l).ok())
               .map(|line| {
                 (isomorph_score(&line), line)
               });

    let ranked =  by_score(scored_lines);
    let (match_score, _) = ranked[0];
    best_score(ranked.into_iter()
      .take_while(|&(score, _)| score - match_score < 2)
      .filter_map(|(_,  line)| {
        best_score(most_frequent(&line).iter().take(3).map(|c| {
          scored_decrypt(&line, *c ^ b' ')
        }))
      }))
    .and_then(|(_score, best)| String::from_utf8(best).ok())
  })
}
