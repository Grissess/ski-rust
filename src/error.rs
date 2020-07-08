#[derive(Debug)]
pub enum Error {
    CodingError(base64::DecodeError),
    InvalidLength(usize),
    BadScheme(String),
    BadEncoding(std::str::Utf8Error),
    SchemeTooLong(std::num::TryFromIntError),
    MissingArgument(String),
    BadNonce([u8; 32]),
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::CodingError(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Error {
        Error::BadEncoding(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Error {
        Error::SchemeTooLong(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
