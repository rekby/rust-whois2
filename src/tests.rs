#[cfg(test)]
use super::*;

#[test]
fn decide_test(){
    let domain = "test.ru";
    let mut whois = WhoisKV::new();
    whois.insert("whois", "whois.root");
    whois.insert("domain", "ru");

    assert_eq!(decide(domain, &whois,vec!()).unwrap(),
               Decision::NextWhois(NextWhois{domain:"ru", whois_server:"whois.root"}));
    assert!(decide(domain, &whois,vec!("whois.root".to_owned())).is_err());
    assert_eq!(decide("ru", &whois, vec!()).unwrap(), Decision::Ok)
}

#[test]
fn get_whois_server_test() {
    let c = Client::new();
    assert_eq!(c.get_whois_server("").unwrap(), ROOT_WHOIS_SERVER.to_owned());
    assert_eq!(c.get_whois_server("ru").unwrap(), ROOT_WHOIS_SERVER.to_owned());
    assert_eq!(c.get_whois_server("test.ru").unwrap(), ROOT_WHOIS_SERVER.to_owned());

    let mut c = Client::new();
    c.good_servers.insert("ru".to_owned(), "whois.ru".to_owned());
    c.good_servers.insert("edu.ru".to_owned(), "whois-test.edu.ru".to_owned());
    c.good_servers.insert("com".to_owned(), "whois-test.com".to_owned());
    c.bad_servers.push("bad".to_owned());
    assert_eq!(c.get_whois_server("").unwrap(), ROOT_WHOIS_SERVER.to_owned());
    assert_eq!(c.get_whois_server("ru").unwrap(), "whois.ru".to_owned());
    assert_eq!(c.get_whois_server("test.ru").unwrap(), "whois.ru".to_owned());
    assert!(c.get_whois_server("test.bad").is_err());
}

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
fn whois_key_value_test() {
    let text = "Domain Name: asd.com
testVal : aAa,
";
    let parsed = whois_key_value(text);
    assert_eq!(parsed.get("Domain Name"), Some(&"asd.com"));
    assert_eq!(parsed.get("testVal"), Some(&"aAa,"));
    assert_eq!(parsed.get("asd"), None);
}
