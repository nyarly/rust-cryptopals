use std::fs::File;
use std::io::{BufRead,BufReader};
use super::utils::*;
use ::byte_convert::*;
use super::frequency::Counts;
use super::frequency::ENGLISH_FREQS;
use super::xor;


/// One of the 60-character strings in this file has been encrypted by single-character XOR.
/// Observe:
///
/// # Examples
/// ```
/// # use cryptopals::set1::challenge4::detect_xor_in_file;
/// assert_eq!(
///   detect_xor_in_file("s3c4-data.txt").unwrap(),
///   "Now that the party is jumping\n"
/// )
/// ```
pub fn detect_xor_in_file(path: &str) -> Option<String> {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    detect_xor(fr)
    .and_then(|best| String::from_utf8(best).ok())
  })
}

pub fn detect_xor<B: BufRead>(fr: B) -> Option<Vec<u8>> {
  let scored_lines = fr.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| hex2bytes(&l).ok())
    .map(|line| (Counts::new(&line), line))
    .map(|(counts, line)|  (counts.isomorph_score(&(*ENGLISH_FREQS)), (counts, line)));

    let ranked =  by_score(scored_lines);
    let (match_score, _) = ranked[0];
    best_score(ranked.into_iter()
      .take_while(|&(score, _)| score - match_score < 2)
      .filter_map(|(_,  (counts,line))| {
        counts.most_congruent_item(&(*ENGLISH_FREQS), 0, |a,b| a^b)
          .map(|(sc, key)| (sc, (key, line.clone())))
      }))
    .map(|(_score, (key, line))| xor::decrypt(&line, key))
}
