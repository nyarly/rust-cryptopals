use std::{fmt, string, error};
use ::serialize::base64;
use std::io;
use crypto;

pub type Result<T> = ::std::result::Result<T, CrackError>;

#[derive(Debug)]
pub enum CrackError {
    Io(io::Error),
    Base64(base64::FromBase64Error),
    Utf8(string::FromUtf8Error),
    Cipher(crypto::symmetriccipher::SymmetricCipherError),
    Str(&'static str),
}

impl fmt::Display for CrackError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CrackError::Cipher(ref e) => write!(f, "Cipher: {:?}", e),
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
            CrackError::Cipher(_) => "Cipher error",
            CrackError::Io(ref e) => e.description(),
            CrackError::Base64(ref e) => e.description(),
            CrackError::Utf8(ref e) => e.description(),
            CrackError::Str(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CrackError::Cipher(_) => None,
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

impl From<crypto::symmetriccipher::SymmetricCipherError> for CrackError {
    fn from(e: crypto::symmetriccipher::SymmetricCipherError) -> CrackError {
        CrackError::Cipher(e)
    }
}
