use std::fs::File;
use std::io::{BufRead,BufReader};
use super::utils::*;
/// One of the 60-character strings in this file has been encrypted by single-character XOR.
///
fn detect_xor(path: &str) -> Option<String> {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    best_score(fr.lines()
               .filter_map(|l| l.ok().map(|ls| ls.into_bytes()))
               .flat_map(|line| {
                 (0..255).map(|c| {
                   scored_decrypt(line.clone(), c)
                 })
               }))
      .and_then(|(_, best)| String::from_utf8(best).ok())
  })
}
