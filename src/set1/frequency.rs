use std::collections::btree_map::BTreeMap;
use std::{iter, ops};
use std::fmt::Display;

#[derive(Clone, Debug)]
pub struct Counts<T> {
  counts: BTreeMap<T, u32>,
  total: u32,
}


pub struct Penalizer<T> {
  penalties: BTreeMap<T, u32>,
}

impl<T: Ord> Penalizer<T> {
  pub fn applied(&self, val: T) -> u32 {
    *self.penalties.get(&val).unwrap_or(&0)
  }
}

lazy_static! {
  pub static ref ENGLISH_FREQS: Counts<u8> = {
    let mut ef = BTreeMap::new();
    ef.insert(b' ', 130); ef.insert(b'e', 127); ef.insert(b'E', 127);
    ef.insert(b't', 90); ef.insert(b'T', 90); ef.insert(b'a', 81);
    ef.insert(b'A', 81); ef.insert(b'o', 75); ef.insert(b'O', 75);
    ef.insert(b'\n', 75); ef.insert(b'\t', 75); ef.insert(b'\r', 75);
    ef.insert(b'i', 69); ef.insert(b'I', 69); ef.insert(b'n', 67);
    ef.insert(b'N', 67); ef.insert(b's', 63); ef.insert(b'S', 63);
    ef.insert(b'h', 60); ef.insert(b'H', 60); ef.insert(b'r', 59);
    ef.insert(b'R', 59); ef.insert(b'd', 42); ef.insert(b'D', 42);
    ef.insert(b'l', 40); ef.insert(b'L', 40); ef.insert(b'c', 27);
    ef.insert(b'C', 27); ef.insert(b'u', 27); ef.insert(b'U', 27);
    Counts{
      counts: ef,
      total: 1000,
    }
  };
}

lazy_static!{
  pub static ref ENGLISH_PENALTIES: Penalizer<u8> = {
    let mut pm = BTreeMap::new();
    for c in 0x00..0x09 {
      pm.insert(c, 100);
    }
    for c in 0x0e..0x20 {
      pm.insert(c, 100);
    }
    pm.insert(0x7f, 100);
    for c in 0x80..0xa6 {
      pm.insert(c, 5);
    }
    for c in 0xa6..0xff {
      pm.insert(c, 15);
    }
    Penalizer{
      penalties: pm
    }
  };
}

use std::borrow::Borrow;
use std::fmt::Debug;

impl<T: Ord + Clone + Debug> Counts<T> {
  pub fn new<L, R>(list: L) -> Counts<T>
    where L: IntoIterator<Item = R>,
          R: ToOwned<Owned = T> + Sized,
          T: Borrow<R>
  {
    let mut fc = BTreeMap::new();
    let mut count = 0;
    for it in list {
      let entry = fc.entry(it.to_owned()).or_insert(0);
      *entry += 1;
      count += 1
    }

    Counts {
      counts: fc,
      total: count,
    }
  }

  fn get(&self, key: T) -> u32 {
    self.counts.get(&key).map(|kr| kr.clone()).unwrap_or(0)
  }

  fn congruent_to(&self, like: &Counts<T>) -> Counts<T> {
    let mut res = BTreeMap::new();
    let mut tc = 0;
    for key in like.counts.keys() {
      res.insert((*key).clone(), self.get((*key).clone()));
      tc += self.get((*key).clone());
    }
    Counts {
      counts: res,
      total: tc,
    }
  }

  pub fn transformed<F: Fn(T) -> U, U: Ord>(&self, f: F) -> Counts<U> {
    let mut res = BTreeMap::new();
    let mut tc = 0;
    for key in self.counts.keys() {
      res.insert(f((*key).clone()), self.get((*key).clone()));
      tc += self.get((*key).clone());
    }
    Counts {
      counts: res,
      total: tc,
    }
  }

  pub fn congruent_score(&self, other: &Counts<T>) -> u32 {
    chisquare(self.congruent_to(other).counts(),
              self.total,
              other.counts(),
              other.total)
  }

  pub fn penalty(&self, ps: &Penalizer<T>) -> u32 {
    self.counts.iter().fold(0,
                            |acc, (key, count)| acc + ps.applied((*key).clone()) * count)
  }


  pub fn isomorph_score(&self, other: &Counts<T>) -> u32 {
    //      println!("ISO:");
    //      println!("self:  {} {:?}", self.total, self.sorted_counts());
    //      println!("other: {} {:?}", other.total, other.sorted_counts());

    let size = self.counts.len();
    let raw = chisquare(self.sorted_counts(),
                        self.total,
                        other.sorted_counts().iter().take(size).cloned(),
                        other.total);
    (raw as f64 * 100.0 / size as f64) as u32
  }

  fn counts(&self) -> Vec<u32> {
    self.counts.values().cloned().collect()
  }

  pub fn sorted_counts(&self) -> Vec<u32> {
    let mut res = self.counts();
    res.sort_by(|l, r| r.cmp(l));
    res
  }

  pub fn most_frequent(&self, threshold: u32) -> Vec<T> {
    let mut s = self.counts.iter().collect::<Vec<_>>();
    s.sort_by(|&(_, l), &(_, r)| r.cmp(l));
    let (_, top) = s[0];
    s.iter()
     .take_while(|&&(_, ref count)| top - *count <= threshold)
     .map(|&(k, _)| k)
     .cloned()
     .collect()
  }


  pub fn most_congruent_item<F: Fn(T, T) -> T>(&self,
                                               against: &Counts<T>,
                                               penalties: &Penalizer<T>,
                                               threshold: u32,
                                               xform: F)
                                               -> Option<(u32, T)> {
    let ref anchor = against.most_frequent(0)[0];
    super::utils::best_score(self.most_frequent(threshold).iter().map(|c| {
      let proposed_key = xform((*c).clone(), (*anchor).clone());
      let xformed = self.transformed(|i| xform(i, proposed_key.clone()));
      (xformed.congruent_score(against) + xformed.penalty(penalties),
       proposed_key)
    }))
  }
}

pub fn english_score(bytes: &[u8]) -> u32 {
  // let fc = frequency_counts(bytes);
  let fc: Counts<u8> = Counts::new(bytes.iter().map(|b| *b));

  fc.congruent_score(&(*ENGLISH_FREQS)) + fc.penalty(&(*ENGLISH_PENALTIES))
}

fn chisquare<I, J>(observed: I, obtot: u32, expected: J, extot: u32) -> u32
  where I: IntoIterator<Item = u32> + Clone,
        J: IntoIterator<Item = u32> + Clone
{
  let factor = obtot as f64 / extot as f64;
  let exs = expected.into_iter().map(|e| e as f64 * factor).collect::<Vec<f64>>();
  let obs = observed.into_iter().map(|o| o as f64).chain(iter::repeat(0.0));
  let sod = squares_of_differences(obs, exs.clone());
  (sod.iter()
      .zip(exs)
      .map(|(sd, ex)| {
        let quotient = sd / ex;
        // println!("{} {} {}", sd, ex, quotient);
        quotient
      })
      .fold(0.0, |acc, n| {
        let sum = acc + n;
        // println!("sum: {} {}", n, sum);
        sum
      }) * 100.0) as u32
}

// XXX consider Chi-square?
// fn rmsd<I>(left: I, right: I) -> u32 where I: IntoIterator<Item=u32> + Clone {
// println!("{:?} vs \n{:?}", left.clone().into_iter().collect::<Vec<_>>(), right.clone().into_iter().collect::<Vec<_>>());
// let sod = squares_of_differences(left, right);
// (sod.iter().fold(0, |acc, n| acc + n) as f64 / sod.len() as f64).sqrt() as u32
// }
//

fn squares_of_differences<L, R, J, D, P>(left: L, right: R) -> Vec<P>
  where L: IntoIterator<Item = J>,
        R: IntoIterator<Item = J>,
        J: ops::Sub<Output = D> + Display + Copy,
        D: ops::Mul<Output = P> + Copy,
        P: Display
{
  left.into_iter()
      .zip(right.into_iter())
      .map(|(l, r)| {
        let d = l - r;
        let sod = d * d;
        // println!("({} - {})**2 = {}", l, r, sod);
        sod
      })
      .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  fn string_score(s: &str) -> u32 {
    let v = String::from(s).into_bytes();
    english_score(&v)
  }

  #[test]
  fn scores_english() {
    assert!(string_score("") == 0, "empty is {}");
    assert!(string_score("Defend the east wall of the castle") - 4505 < 4,
            "practical cryptography example = {}",
            string_score("Defend the east wall of the castle"));
    assert!(string_score("some words") < 100000,
            "some words = {}",
            string_score("some_words"));
    assert!(string_score("some words") < string_score("zxcvbzxcvb"),
            "'some words' = {} 'zxcvbzxcvb' = {}",
            string_score("some words"),
            string_score("zxcvb"));
    assert!(string_score(";;;;;") > 71,
            "';;;;;' = {}",
            string_score(";;;;;"))
  }

}
