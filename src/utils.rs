use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use ipnetwork::IpNetwork;

pub(crate) mod metrics;
pub(crate) mod text;
pub(crate) mod words;

// current_time_ms returns current time as milliseconds
pub fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("could not get time")
        .as_millis() as i64
}

pub fn safe_parse_string_date(d: Option<String>) -> Option<NaiveDateTime> {
    if let Some(d) = d {
        safe_parse_str_date(&d)
    } else {
        None
    }
}

pub fn safe_parse_str_date(d: &str) -> Option<NaiveDateTime> {
    if let Ok(parsed) = NaiveDate::parse_from_str(d, "%Y-%m-%d") {
        return Some(NaiveDateTime::new(parsed, NaiveTime::from_hms(0, 0, 0)));
    }
    if let Ok(parsed) = NaiveDate::parse_from_str(d, "%Y/%m/%d") {
        return Some(NaiveDateTime::new(parsed, NaiveTime::from_hms(0, 0, 0)));
    }
    if let Ok(parsed) = NaiveDate::parse_from_str(d, "%m/%d/%Y") {
        return Some(NaiveDateTime::new(parsed, NaiveTime::from_hms(0, 0, 0)));
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(d, "2001-07-08T00:34:60.026490+09:30") {
        return Some(parsed);
    }
    None
}


pub fn ip_addr_in_network(ip: IpAddr, network: &str) -> bool {
    if let Ok(ip_network) = network.parse::<IpNetwork>() {
        if ip_network.contains(ip) {
            return true;
        }
    }
    false
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    let networks = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/16",
    ];

    for network in &networks {
        if ip_addr_in_network(ip, network) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;
    use chrono::{Datelike};
    use crate::utils::{current_time_ms, ip_addr_in_network, is_private_ip, safe_parse_string_date};

    #[tokio::test]
    async fn test_should_get_current_time_ms() {
        assert!(current_time_ms() > 0);
    }

    #[tokio::test]
    async fn test_should_safe_parse_string_date() {
        assert!(safe_parse_string_date(None) == None);
        assert_eq!(12, safe_parse_string_date(Some("2023-10-12".into())).unwrap().day());
        assert_eq!(12, safe_parse_string_date(Some("2023/10/12".into())).unwrap().day());
        assert_eq!(12, safe_parse_string_date(Some("10/12/2023".into())).unwrap().day());
    }

    #[tokio::test]
    async fn test_should_check_is_private_ip() {
        assert!(is_private_ip(IpAddr::from_str("192.168.1.101").unwrap()));
    }

    #[tokio::test]
    async fn test_should_check_is_ip_addr_in_network() {
        assert!(ip_addr_in_network(IpAddr::from_str("192.168.1.101").unwrap(), "192.168.0.0/16"));
    }
}
