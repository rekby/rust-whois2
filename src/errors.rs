use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    BadWhoisForDomain,
    ConvertToPunycode(idna::Errors),
    WhoisServerLoop(String),
    CantFindWhoisServer,
    Network(std::io::Error),
}

use Error::*;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadWhoisForDomain | CantFindWhoisServer => f.write_str(format!("{:?}", *self).as_str()),
            ConvertToPunycode(errors) => {
                f.write_str(format!("Error convert to punycode: {:?}", errors).as_str())
            }
            WhoisServerLoop(domain) => {
                f.write_str(format!("Whois server loop: {}", domain).as_str())
            }
            Network(err) => Display::fmt(err, f),
        }
    }
}

impl From<idna::Errors> for Error {
    fn from(err: idna::Errors) -> Error {
        ConvertToPunycode(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Network(err)
    }
}
