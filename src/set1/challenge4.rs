use std::fs::File;
use std::io::{BufRead, BufReader};
use utils::*;
use byte_convert::*;
use frequency;
use xor;


/// One of the 60-character strings in this file has been encrypted by single-character XOR.
/// Observe:
///
/// # Examples
/// ```ignore
/// # use cryptopals::set1::challenge4;
/// assert_eq!(
///   challenge4::slow_detect_xor_in_file("s3c4-data.txt"),
///   "Now that the party is jumping\n"
/// );
/// ```
///
pub fn slow_detect_xor_in_file(path: &str) -> String {
  File::open(path)
    .ok()
    .and_then(|f| {
      let fr = BufReader::new(f);
      slow_detect_xor(fr).and_then(|best| String::from_utf8(best).ok())
    })
    .unwrap()
}

pub fn slow_detect_xor<B: BufRead>(fr: B) -> Option<Vec<u8>> {
  let lines = fr.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| hex2bytes(&l).ok())
    .flat_map(|line| {
      full_u8()
        .map(move |key| (line.clone(), xor::decrypt(&line, key), key))
        .map(|(crypt, line, key)| (frequency::english_score(&line), (crypt, line, key)))
    });
  best_score(lines).map(|(score, (crypt, line, key))| {
    println!("solution: {} {} {} {}",
             score,
             key as char,
             String::from_utf8_lossy(&crypt),
             String::from_utf8_lossy(&line));
    line
  })
}

/// # Examples
/// ```
/// # use cryptopals::set1::challenge4;
/// assert_eq!(
///   challenge4::detect_xor_in_file("s3c4-data.txt"),
///   "Now that the party is jumping\n"
/// );
/// ```
pub fn detect_xor_in_file(path: &str) -> String {
  File::open(path)
    .ok()
    .and_then(|f| {
      let fr = BufReader::new(f);
      detect_xor(fr).and_then(|best| String::from_utf8(best).ok())
    })
    .unwrap()
}

pub fn detect_xor<B: BufRead>(fr: B) -> Option<Vec<u8>> {
  let scored_lines = fr.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| hex2bytes(&l).ok())
    .map(|line| {
      let counts = frequency::Counts::<u8>::new::<_, &u8>(&line);
      (counts, line)
    })
    .map(|(counts, line)| {
      let score = counts.isomorph_score(&(*frequency::ENGLISH_FREQS));
      (score, (counts, line))
    });

  let ranked = by_score(scored_lines);
  let (match_score, _) = ranked[0];
  let match_score = match_score + match_score / 20;

  best_score(ranked.into_iter()
      .take_while(|&(score, _)| score < match_score)
      .filter_map(|(_, (counts, line))| {
        counts.most_congruent_item(&(*frequency::ENGLISH_FREQS),
                               &(*frequency::ENGLISH_PENALTIES),
                               0,
                               |a, b| a ^ b)
          .map(|(sc, key)| (sc, (key, line.clone())))
      }))
    .map(|(_score, (key, line))| xor::decrypt(&line, key))
}
