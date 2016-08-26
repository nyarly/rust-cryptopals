/// One of the 60-character strings in this file has been encrypted by single-character XOR.
///
fn detect_xor(path: &str) -> Option<String> {
  let fr = BufReader::new(File::open(path));

  best_score(ft.lines().flat_map(|line| (0..255).map(|c| scored_decrypt(line.clone(), c))))
}
