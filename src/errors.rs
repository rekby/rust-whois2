use std::error::Error as stdErr;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct Error {
    error: String,
}

impl Error {
    pub fn new(error: String)->Error{
        return Error{error}
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result{
        return self.error.fmt(f)
    }
}

impl std::error::Error for Error{

}