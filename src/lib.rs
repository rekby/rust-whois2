// https://habr.com/ru/post/165869/
mod errors;

#[cfg(test)]
mod tests;


use std::collections::HashMap;
use std::io::{Read,Write};
use std::net::TcpStream;
use errors::Error;
use std::hash::Hash;
use std::str::FromStr;

const ROOT_WHOIS_SERVER: &str = "whois.iana.org";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, PartialEq)]
enum Decision<'a> {
    Ok,
    NextWhois(NextWhois<'a>),
}

#[derive(Debug, PartialEq)]
struct NextWhois<'a>{
    domain: &'a str,
    whois_server: &'a str,
}

pub struct Client {
    good_servers: HashMap<String, String>,
    bad_servers: Vec<String>,
}

impl Client {
    pub fn new()->Client{
        let mut res = Client {
            good_servers: HashMap::new(),    
            bad_servers: Vec::new(),
        };
        res.good_servers.insert("".to_owned(), ROOT_WHOIS_SERVER.to_owned());
        return res;
    }

    fn get_whois_server(&self, domain: &str)->Result<String>{
        for subdomain in split_domain(domain) {
            if let Some(server) = self.good_servers.get(subdomain){
                return Ok(server.to_owned());
            };
            if self.bad_servers.iter().any(|x| x == subdomain){
                return Err(Box::new(Error::new("Bad server for whois".to_owned())))
            }
        };
        return Err(Box::new(Error::new("Logical error. Doesn't find whois server".to_owned())));
    }

    pub fn get_whois_string(&mut self, domain: &str)->Result<String>{
        let domain = match idna::domain_to_ascii(domain) {
            Ok(domain) => domain,
            Err(err)=> {
                return Err(Box::new(errors::Error::new(format!("Can't convert domain '{}' to punycode: {:?}", domain, err))));
            },
        };
        let domain= domain.to_lowercase();
        let mut whois_server = self.get_whois_server(&domain)?;
        let mut servers = vec!();

        loop {
            servers.push(whois_server.to_owned());

            let res = ask_server(&whois_server, &domain)?.to_lowercase();
            let whois_kv = whois_key_value(&res);
            match decide(&domain, &whois_kv, &servers)?{
                Decision::Ok => {
                    return Ok(res)
                },
                Decision::NextWhois(next_server) => {
                    whois_server = next_server.whois_server.to_owned();
                    self.good_servers.insert(next_server.domain.to_owned(), next_server.whois_server.to_owned());
                }
            }
        }
    }

    pub fn get_whois_kv(&mut self, domain: &str)->Result<HashMap<String,String>>{
        let whois_string = self.get_whois_string(domain)?;
        let kv = whois_key_value(whois_string.as_str());
        let mut res = HashMap::new();
        for (key, value) in kv.iter(){
            res.insert(key.to_string(), value.to_string());
        };
        return Ok(res);
    }
}

type WhoisKV<'a> = HashMap<&'a str, &'a str>;
fn get_domain<'a>(whois: &'a WhoisKV)->Option<&'a str>{
    for key in &["domain", "domain name"]{
        if let Some(domain) = whois.get(key) {
            return Some(*domain);
        }
    };
    return None;
}

fn next_whois_server<'a>(whois: &'a WhoisKV)->Option<&'a str>{
    match whois.get("whois") {
        Some(domain) => Some(*domain),
        None => None,
    }
}

fn split_domain(domain: &str)->Vec<&str>{
    let domain = domain.trim_matches('.');
    let mut res = vec!(domain);
    if domain.len() == 0 {
        return res;
    }
    
    for (index, _) in domain.match_indices('.'){
        res.push(&domain[index+1..])
    }
    res.push(&domain[0..0]);

    return res;
}

fn ask_server(server: &str, domain: &str)->Result<String>{
    let mut conn = TcpStream::connect((server, 43))?;

    conn.write_all((domain.to_string() + "\r\n").as_bytes())?;
    conn.flush()?;

    let mut res = String::new();
    conn.read_to_string(&mut res)?;
    return Ok(res);
}

fn whois_key_value(text: &str) -> WhoisKV {
    let mut res = HashMap::<&str, &str>::new();
    for line in text.lines(){
        let line = line.trim();
        let mut parts = line.splitn(2, ":");
        if let (Some(key), Some(val)) = (parts.next(), parts.next()){
            res.insert(key.trim(), val.trim());
        }
    };
    return res;
}

fn contains_str(v: &Vec<String>, need: &str) ->bool{
    return v.iter().any(|item| item == need)
}

fn decide<'a>(domain: &'a str, whois: &'a WhoisKV, prev: &Vec<String>) ->Result<Decision<'a>>{
    let whois_domain = get_domain(whois);
    if let Some(whois_domain) = whois_domain {
        if whois_domain == domain {
            return Ok(Decision::Ok);
        }
    };

    let whois_server = if let Some(whois_server) = next_whois_server(whois) {
        let next = NextWhois
        {
            whois_server,
            domain: if let Some(whois_domain) = whois_domain {
                whois_domain
            } else {
                domain
            }
        };
        Some(next)
    } else {
        None
    };
    return if let Some(whois_server) = whois_server {
        if prev.iter().any(|item|item == whois_server.whois_server) {
            Err(Box::new(Error::new("servers loop".to_owned())))
        } else {
            Ok(Decision::NextWhois(whois_server))
        }
    } else {
        Err(Box::new(Error::new("Can't find info about domain/next whois server".to_owned())))
    }
}
