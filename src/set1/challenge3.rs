
fn best_decrypt(crypted: Vec<u8>) -> Vec<u8> {
  let max_score = 0;
  let best = vec!(0);

  for c in (0...255) {
    let trial = decrypt(crypted, vec!(c));
    let score = english_score(trial);

  }
}
