use std::fs::File;
use std::io::{BufRead,BufReader};
use super::utils::*;
/// One of the 60-character strings in this file has been encrypted by single-character XOR.
///
fn detect_xor(path: &str) -> Option<String> {
  File::open(path).ok().and_then(|f| {
    let fr = BufReader::new(f);
    let scored_lines = fr.lines()
               .filter_map(|l| l.ok())
               .flat_map(|line| {
                 let lb = &(line.to_owned().into_bytes());
                 (0..255).map(|c| {
                   scored_decrypt(lb, c)
                 })
               });
    best_score(scored_lines).and_then(|(_, best)| String::from_utf8(best).ok())
  })
}
