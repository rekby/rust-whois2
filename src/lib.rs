// https://habr.com/ru/post/165869/

use std::collections::HashMap;

const initialServer: &str = "whois.iana.org";

struct Client {
    goodServers: HashMap<String, String>,
    badServers: Vec<String>,
}

impl Client {
    fn new()->Client{
        let mut res = Client {
            goodServers: HashMap::new(),
            badServers: Vec::new(),
        };
        res.goodServers.insert("".to_owned(), initialServer.to_owned());
        return res;
    }

    fn get_whois_server(&self, domain: &str)->Option<String>{
        for subdomain in split_domain(domain) {
            if let Some(server) = self.goodServers.get(subdomain){
                return Some(server.to_owned());
            };
            // .contains need create String
            for s in &self.badServers {
                if s == subdomain {
                    return None;
                }
            }
        };
        return None;
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

fn parse_whois(text: &str) -> HashMap<&str, &str>{
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_domain_test() {
        assert_eq!(split_domain(""), vec![""]);
        assert_eq!(split_domain("."), vec![""]);
        assert_eq!(split_domain("ru"), vec!["ru", ""]);
        assert_eq!(split_domain("test.ru"), vec!["test.ru", "ru", ""]);
        assert_eq!(split_domain(".test.ru."), vec!["test.ru", "ru", ""]);
        assert_eq!(split_domain("www.test.ru."), vec!["www.test.ru", "test.ru", "ru", ""]);
    }

    #[test]
    fn get_whois_server_test(){
        let c = Client::new();
        assert_eq!(c.get_whois_server(""), Some(initialServer.to_owned()));
        assert_eq!(c.get_whois_server("ru"), Some(initialServer.to_owned()));
        assert_eq!(c.get_whois_server("test.ru"), Some(initialServer.to_owned()));

        let mut c = Client::new();
        c.goodServers.insert("ru".to_owned(), "whois.ru".to_owned());
        c.goodServers.insert("edu.ru".to_owned(), "whois-test.edu.ru".to_owned());
        c.goodServers.insert("com".to_owned(), "whois-test.com".to_owned());
        c.badServers.push("bad".to_owned());
        assert_eq!(c.get_whois_server(""), Some(initialServer.to_owned()));
        assert_eq!(c.get_whois_server("ru"), Some("whois.ru".to_owned()));
        assert_eq!(c.get_whois_server("test.ru"), Some("whois.ru".to_owned()));
        assert_eq!(c.get_whois_server("test.bad"), None);
    }

    #[test]
    fn parse_whois_test(){
        let text = "Domain Name: asd.com
testVal : aAa,
";
        let parsed = parse_whois(text);
        assert_eq!(parsed.get("Domain Name"), Some(&"asd.com"));
        assert_eq!(parsed.get("testVal"), Some(&"aAa,"));
        assert_eq!(parsed.get("asd"), None);
    }
}
