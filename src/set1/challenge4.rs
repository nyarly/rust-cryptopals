use std::fs::File;
use std::io::{BufRead,BufReader};
use super::utils::*;
use ::byte_convert::*;
use super::frequency;
use super::xor;


/// One of the 60-character strings in this file has been encrypted by single-character XOR.
/// Observe:
///
/// # Examples
/// ```
/// # use cryptopals::set1::challenge4;
/// //assert_eq!(
/// //  challenge4::slow_detect_xor_in_file("s3c4-data.txt"),
/// //  "Now that the party is jumping\n"
/// //);
/// assert_eq!(
///   challenge4::detect_xor_in_file("s3c4-data.txt"),
///   "Now that the party is jumping\n"
/// );
/// panic!("want to see output")
/// ```
pub fn slow_detect_xor_in_file(path: &str) -> String {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    slow_detect_xor(fr)
    .and_then(|best| String::from_utf8(best).ok())
  }).unwrap()
}

pub fn slow_detect_xor<B: BufRead>(fr: B) -> Option<Vec<u8>> {
  let lines = fr.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| hex2bytes(&l).ok())

    .flat_map(|line| {
      full_u8().map(move |key| (xor::decrypt(&line, key), key))
        .map(|(line, key)| (frequency::english_score(&line), (line, key)))
        .inspect(|&(score, (ref line, key))| println!("after  decrypt: {} <{}> {}", key, String::from_utf8_lossy(&line), score))
  });
  best_score(lines).map(|(_score, (line, _key))| line)
}

pub fn detect_xor_in_file(path: &str) -> String {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    detect_xor(fr)
    .and_then(|best| String::from_utf8(best).ok())
  }).unwrap()
}

pub fn detect_xor<B: BufRead>(fr: B) -> Option<Vec<u8>> {
  let scored_lines = fr.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| hex2bytes(&l).ok())
    .map(|line| (frequency::Counts::new(&line), line))
    .map(|(counts, line)|  (counts.isomorph_score(&(*frequency::ENGLISH_FREQS)), (counts, line)));

    let ranked =  by_score(scored_lines);
    let (match_score, _) = ranked[0];

    best_score(
      ranked.into_iter()
      .inspect(|&(score, (ref counts, ref line))| println!("{} {:?} {}", score, counts, String::from_utf8_lossy(&line)))
      .take_while(|&(score, _)| score - match_score < 300)
      .filter_map(|(_,  (counts,line))| {
        counts.most_congruent_item(&(*frequency::ENGLISH_FREQS), &(*frequency::ENGLISH_PENALTIES), 0, |a,b| a^b)
          .map(|(sc, key)| (sc, (key, line.clone())))
      })
      .inspect(|&(score, (ref counts, ref line))| println!("{} {:?} {}", score, counts, String::from_utf8_lossy(&line)))
      ).map(|(_score, (key, line))| xor::decrypt(&line, key))
}
