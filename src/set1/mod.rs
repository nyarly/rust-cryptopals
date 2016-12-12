pub mod challenge1;
// pub mod challenge2;
// pub mod challenge3;
pub mod challenge4;
pub mod challenge5;
pub mod challenge6;
pub mod challenge7;
pub mod challenge8;

mod frequency;

/// The hex encoded string:
///
/// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// # Examples
///
/// ```
/// # use cryptopals::set1::best_hex_decrypt;
///
/// let best = best_hex_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
/// assert_eq!(
///   String::from_utf8(best).unwrap(),
///   "Cooking MC's like a pound of bacon"
/// )
/// ```
use ::byte_convert::*;
pub fn best_hex_decrypt(encrypted: &str) -> Vec<u8> {
    let cstr = hex2bytes(encrypted).unwrap();

    best_decrypt(&cstr)
}

pub fn best_decrypt(cstr: &[u8]) -> Vec<u8> {
    let (_, best) = utils::best_score(utils::full_u8().map(|c| xor::scored_decrypt(&cstr, c)))
                        .unwrap_or_else(|| (0, xor::decrypt(&cstr, b'0')));
    best
}


mod utils {
    pub fn full_u8() -> Box<Iterator<Item = u8>> {
        Box::new((0..128).chain((0..128).map(|n| n + 128)))
    }

    use std::fmt::Debug;
    pub fn best_score<I, S, V>(list: I) -> Option<(S, V)>
        where I: Iterator<Item = (S, V)>,
              S: Ord + Clone + Debug,
              V: Debug
    {
        list.min_by_key(|&(ref score, _)| score.clone())
    }

    pub fn by_score<I, S, V>(list: I) -> Vec<(S, V)>
        where I: Iterator<Item = (S, V)>,
              S: Ord + Clone,
              V: Clone
    {
        let mut v = list.collect::<Vec<_>>();
        v.sort_by_key(|&(ref score, _)| score.clone());
        v
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn full_u8_is_goes_to_255() {
            assert_eq!(full_u8().last().unwrap(), 255u8)
        }
    }
}

mod xor {
    use std::ops::BitXor;
    use std::iter::{self, FromIterator, IntoIterator};

    pub fn scored_decrypt(crypted: &[u8], key: u8) -> (u32, Vec<u8>) {
        let trial = decrypt(crypted, key);
        let score = super::frequency::english_score(&trial);
        // println!("{:?} {:?}", score, String::from_utf8(trial.clone()).unwrap_or(String::from("no")));
        (score, trial)
    }

    pub fn xor_iters<I, J, K, V>(pvec: I, kvec: J) -> K
        where I: IntoIterator<Item = V>,
              J: IntoIterator<Item = V>,
              K: FromIterator<<V as BitXor>::Output>,
              V: BitXor
    {
        pvec.into_iter()
            .zip(kvec)
            .map(|(p, k)| p ^ k)
            .collect()
    }

    pub fn decrypt(crypted: &[u8], key: u8) -> Vec<u8> {
        xor_iters(crypted, iter::repeat(&key))
    }


    #[cfg(test)]
    mod tests {
        use super::*;
        use ::byte_convert::*;
        use num_bigint::BigInt;
        use num::cast::ToPrimitive;

        fn make_string(bytes: Vec<u8>) -> String {
            String::from_utf8(bytes).unwrap()
        }

        #[test]
        fn example_xor() {
            assert_eq!(make_string(xor_iters(hex2bytes("1c0111001f010100061a024b53535009181c")
                                                 .unwrap(),
                                             hex2bytes("686974207468652062756c6c277320657965")
                                                 .unwrap())),
                       make_string(hex2bytes("746865206b696420646f6e277420706c6179").unwrap()))
        }

        #[test]
        fn can_bigint_from_hex() {
            assert_eq!(BigInt::to_u32(&hex2bigint("a7").unwrap()).unwrap(), 167)
        }

        #[test]
        fn double_decrypt() {
            let orig = String::from("1234").into_bytes();
            let d = decrypt(&orig, 138);
            let p = decrypt(&d, 138);
            assert_eq!(orig, p)
        }
    }
}
