use std::{fmt, string, error, iter};
use std::fs::File;
use std::io::{self, BufReader, Read};
use super::utils::*;
use super::frequency;
use ::serialize::base64::{self, FromBase64};

#[derive(Debug)]
pub enum CrackError {
    Io(io::Error),
    Base64(base64::FromBase64Error),
    Utf8(string::FromUtf8Error),
    Str(&'static str),
}

impl fmt::Display for CrackError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CrackError::Io(ref e) => write!(f, "IO: {}", e),
            CrackError::Base64(ref e) => write!(f, "Base64: {}", e),
            CrackError::Utf8(ref e) => write!(f, "Utf8: {}", e),
            CrackError::Str(ref e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for CrackError {
    fn description(&self) -> &str {
        match *self {
            CrackError::Io(ref e) => e.description(),
            CrackError::Base64(ref e) => e.description(),
            CrackError::Utf8(ref e) => e.description(),
            CrackError::Str(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CrackError::Io(ref e) => Some(e),
            CrackError::Base64(ref e) => Some(e),
            CrackError::Utf8(ref e) => Some(e),
            CrackError::Str(_) => None,
        }
    }
}

impl From<io::Error> for CrackError {
    fn from(e: io::Error) -> CrackError {
        CrackError::Io(e)
    }
}
impl From<base64::FromBase64Error> for CrackError {
    fn from(e: base64::FromBase64Error) -> CrackError {
        CrackError::Base64(e)
    }
}
impl From<string::FromUtf8Error> for CrackError {
    fn from(e: string::FromUtf8Error) -> CrackError {
        CrackError::Utf8(e)
    }
}
impl From<&'static str> for CrackError {
    fn from(e: &'static str) -> CrackError {
        CrackError::Str(e)
    }
}


/// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
///
/// Decrypt it.
/// Here's how:
/// # Examples
/// ```
/// use ::cryptopals::set1::challenge6::crack_repeating_key_xor;
/// let answer = crack_repeating_key_xor("s1c6.txt").unwrap();
/// let (keysize, key, result) = answer;
/// //for ch in result.as_bytes().chunks(keysize) {
///   //println!("{:?}", String::from_utf8_lossy(ch))
/// //}
/// assert_eq!(keysize, 5);
/// assert_eq!(key, String::from("innnn"));
/// assert_eq!(result, String::from("another thing"))
pub fn crack_repeating_key_xor(path: &str) -> Result<(usize, String, String), CrackError> {
    let file = try!(File::open(path));
    let mut buf = BufReader::new(file);
    let mut b64bytes = Vec::new();
    try!(buf.read_to_end(&mut b64bytes));

    let crypted = try!(b64bytes.from_base64());
    for it in crypted.clone() {
        print!("{:?},", it)
    }
    println!("");

    let keysize = try!(pick_keysize(&crypted));
    let key = try!(String::from_utf8((0..keysize)
        .map(|offset| key_for_slice(&crypted, offset, keysize).unwrap())
        .collect()));
    let cryptstr = try!(String::from_utf8(crypted));
    Ok((keysize,
        key.clone(),
        try!(super::challenge5::repeating_key_xor(&cryptstr, &key).ok_or("empty crypt"))))
}

fn hamming(left: &str, right: &str) -> u32 {
    left.bytes().zip(right.bytes()).fold(0, |dist, (lb, rb)| (lb ^ rb).count_ones() + dist)
}

fn pick_keysize(crypted: &[u8]) -> Result<usize, CrackError> {
    best_score((2..40).map(|a_keysize| {
            let mut chunks = crypted.chunks(a_keysize);
            let a = chunks.next().unwrap();
            let pair = (((chunks.take(3)
                .fold(0, |acc, chunk| {
                    acc +
                    hamming(&String::from_utf8(a.to_vec()).unwrap(),
                            &String::from_utf8(chunk.to_vec()).unwrap())
                }) as f64 / a_keysize as f64) * 100.0) as u32,
                        a_keysize);
            // println!("{:?}", pair);
            pair
        }))
        .map(|(_sc, ks)| ks)
        .ok_or(CrackError::Str("empty keysize range"))
}

fn get_slice<'g>(crypted: &'g [u8], offset: usize, keysize: usize) -> Vec<u8> {
    crypted.iter()
        .enumerate()
        .filter_map(|(i, ref c)| if i % keysize == offset {
            Some(*c)
        } else {
            None
        }).cloned().collect()
}

fn key_for_slice(crypted: &[u8], offset: usize, keysize: usize) -> Option<u8> {
    let slice = get_slice(crypted, offset, keysize);
    frequency::Counts::new(slice)
        .most_congruent_item(&(*frequency::ENGLISH_FREQS),
                             &(*frequency::ENGLISH_PENALTIES),
                             0,
                             |a, b| a ^ b)
        .map(|(_sc, key)| key)
}

#[cfg(test)]
mod test {
    #[test]
    fn get_slice() {
        let t = "0123456789".as_bytes();
        assert_eq!(String::from_utf8(super::get_slice(t, 0, 2)
                                     .iter().cloned().collect()).unwrap(),
                   String::from("02468"));
        assert_eq!(super::get_slice(t, 1, 2), "13579");
        assert_eq!(super::get_slice(t, 0, 3), "0369");
        assert_eq!(super::get_slice(t, 1, 3), "147");
        assert_eq!(super::get_slice(t, 2, 3), "258");
    }


    #[test]
    fn hamming() {
        assert_eq!(super::hamming("this is a test", "wokka wokka!!!"), 37)
    }

}
