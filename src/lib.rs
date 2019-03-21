#[macro_use]
extern crate nom;
use chrono::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str;
use std::str::FromStr;
use http;

named!(parse_ipv4 <&str, Ipv4Addr>,
    map_res!(
        take_until_and_consume!(" "),
        |s: &str| s.parse()
    )
);

named!(parse_ipv6 <&str, Ipv6Addr>,
    map_res!(
        take_until_and_consume!(" "),
        |s: &str| s.parse()
    )
);

named!(parse_ip <&str, IpAddr>,
    alt!(
        parse_ipv4 => { |ip:Ipv4Addr| IpAddr::V4(ip) } |
        parse_ipv6 => { |ip:Ipv6Addr| IpAddr::V6(ip) }
    )
);

named!(parse_date <&str, DateTime<FixedOffset>>,
    map_res!(
        delimited!(
            tag!("["),
            take_until!("]"),
            tag!("]")
        ),
        |s| DateTime::parse_from_str(s, "%d/%h/%Y:%H:%M:%S %z")
    )
);

named!(parse_identd_user <&str, Option<String>>,
    alt!(
        tag!("- ") => { |_| None } |
        opt!(
            map!(
                take_until_and_consume!(" "),
                |u| u.into()
            )
        )
    )
);

named!(parse_user <&str, Option<String>>,
    alt!(
        tag!("- ") => { |_| None } |
        opt!(
            map!(
                take_until_and_consume!(" "),
                |u| u.into()
            )
        )
    )
);

named!(parse_request <&str, http::Request<()>>,
    map_res!(
        delimited!(
            tag!(r#"""#),
            do_parse!(
                method: take_until_and_consume!(" ") >>
                path: take_until_and_consume!(" ") >>
                proto_ver: alt!(
                    tag!("HTTP/1.0") => { |_| http::Version::HTTP_10 } |
                    tag!("HTTP/1.1") => { |_| http::Version::HTTP_11 } |
                    tag!("HTTP/2.0") => { |_| http::Version::HTTP_2 }
                ) >>
                (http::Request::builder().method(method).uri(path).version(proto_ver).body(()))
            ),  
            tag!(r#"""#)
        ),
        |req| req
    )
);

named!(parse_http_status <&str, http::StatusCode>,
    map_res!(
        take_until_and_consume!(" "),
        |s: &str| http::StatusCode::from_str(s)
    )
);

named!(parse_bytes <&str, u32>,
    map_res!(
        alt_complete!(
            take_until_and_consume!(" ") |
            nom::rest
        ),
        |s: &str| s.parse()
    )
);

named!(parse_referrer <&str, Option<http::Uri>>,
    map_res!(
        delimited!(
            tag!(r#"""#),
            take_until!(r#"""#),
            tag!(r#"""#)
        ),
        |s: &str| {
            if s.trim() == "-" {
                return Ok(None)
            } else {
                match s.parse() {
                    Ok(uri) => Ok(Some(uri)),
                    Err(e) => Err(e),
                }
            }
        }
    )
);

named!(parse_user_agent <&str, String>,
    map!(
        delimited!(
            tag!(r#"""#),
            take_until!(r#"""#),
            tag!(r#"""#)
        ),
        |ua| ua.into()
    )
);

#[derive(Debug)]
pub struct CommonLogEntry {
    pub ip: IpAddr,
    pub identd_user: Option<String>,
    pub user: Option<String>,
    pub timestamp: DateTime<FixedOffset>,
    pub request: http::Request<()>,
    pub status_code: http::StatusCode,
    pub bytes: u32,
}

named!(pub parse_common_log <&str, CommonLogEntry>,
    do_parse!(
        ip: parse_ip >>
        identd_user: parse_identd_user >>
        user: parse_user >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes: parse_bytes >>
        (CommonLogEntry { ip, identd_user, user, timestamp, request, status_code, bytes })
    )
);

#[derive(Debug)]
pub struct CombinedLogEntry {
    pub ip: IpAddr,
    pub identd_user: Option<String>,
    pub user: Option<String>,
    pub timestamp: DateTime<FixedOffset>,
    pub request: http::Request<()>,
    pub status_code: http::StatusCode,
    pub bytes: u32,
    pub referrer: Option<http::Uri>,
    pub user_agent: String,
}

named!(pub parse_combined_log <&str, CombinedLogEntry>,
    do_parse!(
        ip: parse_ip >>
        identd_user: parse_identd_user >>
        user: parse_user >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes: parse_bytes >>
        referrer: parse_referrer >>
        tag!(" ") >>
        user_agent: parse_user_agent >>
        (CombinedLogEntry { ip, identd_user, user, timestamp, request, status_code, bytes, referrer, user_agent })
    )
);

#[cfg(test)]
mod tests {
    use super::*;
    use nom::Context::Code;
    use nom::Err::Error;
    use nom::Err::Incomplete;
    use nom::ErrorKind::MapRes;
    use nom::Needed::Size;

    #[test]
    fn test_parse_date() {
        let expected = FixedOffset::west(7 * 3600)
            .ymd(2000, 10, 10)
            .and_hms(13, 55, 36);

        assert_eq!(
            parse_date("[10/Oct/2000:13:55:36 -0700]"),
            Ok(("", expected))
        );

        assert_eq!(
            parse_date("[10/Oct/2000:13:55:36]"),
            Err(Error(Code("[10/Oct/2000:13:55:36]", MapRes)))
        );
    }

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(
            parse_ipv4("127.0.0.1 "),
            Ok(("", Ipv4Addr::new(127, 0, 0, 1)))
        );

        assert_eq!(parse_ipv4(""), Err(Incomplete(Size(1))));
        assert_eq!(parse_ipv4("251."), Err(Incomplete(Size(1))));

        assert_eq!(parse_ipv4("251. "), Err(Error(Code("251. ", MapRes))));
        assert_eq!(
            parse_ipv4("256.256.256.256 "),
            Err(Error(Code("256.256.256.256 ", MapRes)))
        );
    }

    #[test]
    fn test_parse_ipv6() {
        assert_eq!(
            parse_ipv6("::1 "),
            Ok(("", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );

        assert_eq!(parse_ipv6(""), Err(Incomplete(Size(1))));
        assert_eq!(parse_ipv6("::"), Err(Incomplete(Size(1))));
    }

    #[test]
    fn test_parse_ip() {
        assert_eq!(
            parse_ip("127.0.0.1 "),
            Ok(("", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
        );

        assert_eq!(
            parse_ip("::1 "),
            Ok(("", IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))))
        );
    }

    #[test]
    fn test_parse_identd_user() {
        // https://tools.ietf.org/html/rfc1413
        assert_eq!(parse_identd_user("- "), Ok(("", None)));
        assert_eq!(
            parse_identd_user("user-identifier "),
            Ok(("", Some(String::from("user-identifier"))))
        );
    }

    #[test]
    fn test_parse_user() {
        assert_eq!(parse_user("- "), Ok(("", None)));
        assert_eq!(parse_user("daniel "), Ok(("", Some(String::from("daniel")))));
    }

    #[test]
    fn test_parse_request() {
        let res = parse_request(r#""GET /apache_pb.gif HTTP/1.0""#);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, ""); // nothing left in buffer
        let res = res.1;
        assert_eq!(res.method(), http::Method::GET);
        assert_eq!(res.uri(), "/apache_pb.gif");
        assert_eq!(res.version(), http::Version::HTTP_10);
    }

    #[test]
    fn test_parse_bytes() {
        assert_eq!(parse_bytes("1234"), Ok(("", 1234)));
        assert_eq!(parse_bytes("1234 "), Ok(("", 1234)));
        assert_eq!(parse_bytes(""), Err(Error(Code("", MapRes))));
    }

    #[test]
    fn test_parse_http_status() {
        assert_eq!(parse_http_status("404 "), Ok(("", http::StatusCode::NOT_FOUND)));
        assert_eq!(parse_http_status("418 "), Ok(("", http::StatusCode::IM_A_TEAPOT)));
        assert_eq!(parse_http_status(" "), Err(Error(Code(" ", MapRes))));
    }

    #[test]
    fn test_parse_common_log_entry() {
        let entry = parse_common_log(r#"127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326"#);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(entry.identd_user.is_some());
        assert_eq!(entry.identd_user.unwrap(), "user-identifier");
        assert!(entry.user.is_some());
        assert_eq!(entry.user.unwrap(), "frank");
        assert_eq!(entry.timestamp, FixedOffset::west(7 * 3600).ymd(2000, 10, 10).and_hms(13, 55, 36));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/apache_pb.gif");
        assert_eq!(entry.request.version(), http::Version::HTTP_10);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 2326);
    }

    #[test]
    fn test_parse_common_log_ipv6() {
        let entry = parse_common_log(r#"2001:8a0:fa0d:ba01:5db0:ae0f:8444:161c - - [02/Mar/2019:17:39:56 +0000] "GET / HTTP/1.1" 200 66503"#);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, IpAddr::V6(Ipv6Addr::new(0x2001, 0x8a0, 0xfa0d, 0xba01, 0x5db0, 0xae0f, 0x8444, 0x161c)));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(entry.timestamp, FixedOffset::west(0).ymd(2019, 3, 2).and_hms(17, 39, 56));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/");
        assert_eq!(entry.request.version(), http::Version::HTTP_11);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 66503);
    }

    #[test]
    fn test_parse_common_log_entry_more() {
        let entry = parse_common_log(r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612"#);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(entry.timestamp, FixedOffset::west(0).ymd(2019, 3, 15).and_hms(3, 17, 5));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/");
        assert_eq!(entry.request.version(), http::Version::HTTP_11);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 612);
    }

    #[test]
    fn test_parse_referrer() {
        let uri = parse_referrer(r#""http://www.example.com/query""#);
        assert!(uri.is_ok());
        let uri = uri.unwrap().1;
        assert!(uri.is_some());
        let uri = uri.unwrap();
        assert_eq!("/query", uri.path());
        assert_eq!("www.example.com", uri.host().unwrap());

        assert!(parse_referrer(r#""-""#).unwrap().1.is_none());
    }

    #[test]
    fn test_parse_user_agent() {
        let agent = parse_user_agent(r#""Mozilla/4.08 [en] (Win98; I ;Nav)""#);
        assert!(agent.is_ok());
        let agent = agent.unwrap().1;
        assert_eq!(agent, "Mozilla/4.08 [en] (Win98; I ;Nav)");
    }

    #[test]
    fn test_parse_combined_log_entry() {
        let entry = parse_combined_log(r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)""#);
        println!("{:?}", entry);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_some());
        assert_eq!(entry.user.unwrap(), "frank");
        assert_eq!(entry.timestamp, FixedOffset::west(7 * 3600).ymd(2000, 10, 10).and_hms(13, 55, 36));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/apache_pb.gif");
        assert_eq!(entry.request.version(), http::Version::HTTP_10);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 2326);
        assert!(entry.referrer.is_some());
        let referrer = entry.referrer.unwrap();
        assert_eq!(referrer.path(), "/start.html");
        assert_eq!(referrer.host().unwrap(), "www.example.com");
        assert_eq!(entry.user_agent, "Mozilla/4.08 [en] (Win98; I ;Nav)");
    }

    #[test]
    fn test_parse_combined_log_entry_more() {
        let entry = parse_combined_log(r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1""#);
        println!("{:?}", entry);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(entry.identd_user.is_none());
        assert!(entry.user.is_none());
        assert_eq!(entry.timestamp, FixedOffset::west(0).ymd(2019, 3, 15).and_hms(3, 17, 5));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/");
        assert_eq!(entry.request.version(), http::Version::HTTP_11);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes, 612);
        assert!(entry.referrer.is_none());
        assert_eq!(entry.user_agent, "curl/7.52.1");
    }
}
