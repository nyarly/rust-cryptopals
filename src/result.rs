use std::{fmt, string, error};
use ::serialize::base64;
use std::io;

type Result<T> = ::std::result::Result<T, CrackError>;

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
