use nom::*;
use chrono::prelude::*;
use std::net::IpAddr;
use http;
use super::XForwardedProto;

named!(parse_ip <&str, IpAddr>,
    flat_map!(take_until_and_consume!(" "), parse_to!(IpAddr))
);

named!(parse_date <&str, DateTime<FixedOffset>>,
    map_res!(
        delimited!(
            tag!("["),
            take_until!("]"),
            tag!("]")
        ),
        |s| {
            DateTime::parse_from_str(s, "%d/%h/%Y:%H:%M:%S %z")
                .or_else(|_e| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%z"))
                .or_else(|_e| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%z"))
                .or_else(|_e| DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z"))
                .or_else(|_e| DateTime::parse_from_rfc2822(s))
                .or_else(|_e| DateTime::parse_from_rfc3339(s))
        }
    )
);

named!(parse_identd_user <&str, Option<&str>>,
    alt!(
        tag!("- ") => { |_| None } |
        opt!(
            take_until_and_consume!(" ")
        )
    )
);

named!(parse_user <&str, Option<&str>>,
    alt!(
        tag!("- ") => { |_| None } |
        opt!(
            take_until_and_consume!(" ")
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
    flat_map!(take_until_and_consume!(" "), parse_to!(http::StatusCode))
);

named!(parse_bytes <&str, u32>,
    flat_map!(alt_complete!(take_until_and_consume!(" ") | rest), parse_to!(u32))
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

named!(parse_user_agent <&str, Option<&str>>,
    alt!(
        tag!(r#""-""#) => {|_tag| None } |
        opt!(
            delimited!(
                tag!(r#"""#),
                take_until!(r#"""#),
                tag!(r#"""#)
            )
        )
    )
);

named!(parse_ip_and_port <&str, (Option<IpAddr>, Option<u16>)>,
    alt!(
        tag!("-") => {|_tag| (None, None) } |
        do_parse!(
            ip: opt!(flat_map!(take_until_and_consume!(":"), parse_to!(IpAddr))) >>
            port: opt!(flat_map!(take_until!(r#"""#), parse_to!(u16))) >>
            ((ip, port))
        )
    )
);

named!(parse_x_forwarded_for <&str, Vec<IpAddr>>,
    do_parse!(
        tag!("x_forwarded_for:") >>
        ips: delimited!(
            tag!(r#"""#),
            separated_list_complete!(tag!(", "), 
                flat_map!(alt_complete!(take_until!(",") | take_until!(r#"""#)), parse_to!(IpAddr))),
            tag!(r#"""#)
        ) >>
        (ips)
    )
);

named!(parse_x_forwarded_proto <&str, XForwardedProto>,
    do_parse!(
        tag!("x_forwarded_proto:") >>
        x_forwarded_for: delimited!(
            tag!(r#"""#),
            alt!(
                tag!("https") => { |_proto| XForwardedProto::HTTPS } |
                tag!("http") => { |_proto| XForwardedProto::HTTP }
            ),
            tag!(r#"""#)
        ) >>
        (x_forwarded_for)
    )
);

named!(parse_vcap_request_id <&str, &str>,
    do_parse!(
        tag!("vcap_request_id:") >>
        vcap_request_id: delimited!(
            tag!(r#"""#),
            take_until!(r#"""#),
            tag!(r#"""#)
        ) >>
        (vcap_request_id)
    )
);

named!(parse_response_time <&str, f32>,
    do_parse!(
        tag!("response_time:") >>
        response_time: flat_map!(alt_complete!(recognize_float | rest), parse_to!(f32)) >>
        (response_time)
    )
);

named!(parse_app_id <&str, Option<&str>>,
    alt!(
        tag!(r#"app_id:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("app_id:") >>
                vcap_request_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (vcap_request_id)
            )
        )
    )
);

named!(parse_app_index <&str, Option<u16>>,
    alt!(
        tag!(r#"app_index:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("app_index:") >>
                vcap_request_id: delimited!(
                    tag!(r#"""#),
                    flat_map!(take_until!(r#"""#), parse_to!(u16)),
                    tag!(r#"""#)
                ) >>
                (vcap_request_id)
            )
        )
    )
);

named!(parse_trace_id <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        tag!(r#"x_b3_traceid:"-""#) => {|_tag| None} |
        opt!(
            do_parse!(
                tag!("x_b3_traceid:") >>
                trace_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (trace_id)
            )
        )
    )
);

named!(parse_span_id <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        tag!(r#"x_b3_spanid:"-""#) => {|_tag| None } |
        opt!(
            do_parse!(
                tag!("x_b3_spanid:") >>
                span_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (span_id)
            )
        )
    )
);

named!(parse_parent_span_id <&str, Option<&str>>,
    alt!(
        not!(complete!(non_empty)) => {|_tag| None} |
        tag!(r#"x_b3_parentspanid:"-""#) => {|_tag| None} |
        opt!(
            do_parse!(
                tag!("x_b3_parentspanid:") >>
                parent_span_id: delimited!(
                    tag!(r#"""#),
                    take_until!(r#"""#),
                    tag!(r#"""#)
                ) >>
                (parent_span_id)
            )
        )
    )
);

named!(pub(crate) parse_common_log <&str, super::CommonLogEntry>,
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
        (super::CommonLogEntry { ip, identd_user, user, timestamp, request, status_code, bytes })
    )
);

named!(pub(crate) parse_combined_log <&str, super::CombinedLogEntry>,
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
        (super::CombinedLogEntry { ip, identd_user, user, timestamp, request, status_code, bytes, referrer, user_agent })
    )
);

named!(pub(crate) parse_gorouter_log <&str, super::GorouterLogEntry>,
    do_parse!(
        request_host: take_until_and_consume!(" ") >>
        tag!("- ") >>
        timestamp: parse_date >>
        tag!(" ") >>
        request: parse_request >>
        tag!(" ") >>
        status_code: parse_http_status >>
        bytes_received: parse_bytes >>
        bytes_sent: parse_bytes >>
        referrer: parse_referrer >>
        tag!(" ") >>
        user_agent: parse_user_agent >>
        tag!(" ") >>
        remote_addr: delimited!(tag!(r#"""#), parse_ip_and_port, tag!(r#"""#)) >>
        tag!(" ") >>
        backend_addr: delimited!(tag!(r#"""#), parse_ip_and_port, tag!(r#"""#)) >>
        tag!(" ") >>
        x_forwarded_for: parse_x_forwarded_for >>
        tag!(" ") >>
        x_forwarded_proto: parse_x_forwarded_proto >>
        tag!(" ") >>
        vcap_request_id: parse_vcap_request_id >>
        tag!(" ") >>
        response_time: parse_response_time >>
        tag!(" ") >>
        app_id: parse_app_id >>
        tag!(" ") >>
        app_index: parse_app_index >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | tag!(" ")) >>
        trace_id: parse_trace_id >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | tag!(" ")) >>
        span_id: parse_span_id >>
        alt!(not!(complete!(non_empty)) => {|_tag| ""} | tag!(" ")) >>
        parent_span_id: parse_parent_span_id >>
        ({
            super::GorouterLogEntry { 
                request_host,
                timestamp, 
                request, 
                status_code, 
                bytes_received, 
                bytes_sent, 
                referrer, 
                user_agent, 
                remote_addr: remote_addr.0.unwrap(), // should always be there
                remote_port: remote_addr.1.unwrap(), // should always be there
                backend_addr: backend_addr.0, 
                backend_port: backend_addr.1, 
                x_forwarded_for, 
                x_forwarded_proto, 
                vcap_request_id, 
                response_time, 
                app_id, 
                app_index,
                trace_id,
                span_id,
                parent_span_id,
            }
        })
    )
);

#[cfg(test)]
mod tests {
    use super::*;
    use nom::Context::Code;
    use nom::Err::Error;
    use nom::ErrorKind::{MapRes, ParseTo};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_date() {
        let expected = FixedOffset::west(7 * 3600)
            .ymd(2000, 7, 25)
            .and_hms(13, 55, 36);

        assert_eq!(
            parse_date("[25/Jul/2000:13:55:36 -0700]"),
            Ok(("", expected))
        );
        
        assert_eq!(
            parse_date("[2000-07-25 13:55:36-0700]"),
            Ok(("", expected))
        );

        assert_eq!(
            parse_date("[2000-07-25T13:55:36-07:00]"),
            Ok(("", expected))
        );

        assert_eq!(
            parse_date("[Tue, 25 Jul 2000 13:55:36 -0700]"),
            Ok(("", expected))
        );

        let expected = FixedOffset::west(7 * 3600)
            .ymd(2000, 7, 25)
            .and_hms_milli(13, 55, 36, 499);

        assert_eq!(
            parse_date("[2000-07-25T13:55:36.499-0700]"),
            Ok(("", expected))
        );

        assert_eq!(
            parse_date("[10/Oct/2000:13:55:36]"),
            Err(Error(Code("[10/Oct/2000:13:55:36]", MapRes)))
        );
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
            Ok(("", Some("user-identifier")))
        );
    }

    #[test]
    fn test_parse_user() {
        assert_eq!(parse_user("- "), Ok(("", None)));
        assert_eq!(parse_user("daniel "), Ok(("", Some("daniel"))));
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
        assert_eq!(parse_bytes(""), Err(Error(Code("", ParseTo))));
    }

    #[test]
    fn test_parse_http_status() {
        assert_eq!(parse_http_status("404 "), Ok(("", http::StatusCode::NOT_FOUND)));
        assert_eq!(parse_http_status("418 "), Ok(("", http::StatusCode::IM_A_TEAPOT)));
        assert_eq!(parse_http_status(" "), Err(Error(Code("", ParseTo))));
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
        assert!(agent.is_some());
        let agent = agent.unwrap();
        assert_eq!(agent, "Mozilla/4.08 [en] (Win98; I ;Nav)");

        let agent = parse_user_agent(r#""-""#);
        println!("{:#?}", agent);
        assert!(agent.is_ok());
        let agent = agent.unwrap().1;
        assert!(agent.is_none());
    }

    #[test]
    fn test_parse_x_forwarded_for() {
        let x_forwarded_for = parse_x_forwarded_for(r#"x_forwarded_for:"10.10.10.1, 10.10.10.2""#);
        assert!(x_forwarded_for.is_ok());
        let x_forwarded_for = x_forwarded_for.unwrap().1;
        assert_eq!(x_forwarded_for, vec![IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                                         IpAddr::V4(Ipv4Addr::new(10, 10, 10, 2))]);
    }

    #[test]
    fn test_parse_x_forwarded_proto() {
        let x_forwarded_proto = parse_x_forwarded_proto(r#"x_forwarded_proto:"https""#);
        assert!(x_forwarded_proto.is_ok());
        let x_forwarded_proto = x_forwarded_proto.unwrap().1;
        assert_eq!(x_forwarded_proto, XForwardedProto::HTTPS);

        let x_forwarded_proto = parse_x_forwarded_proto(r#"x_forwarded_proto:"https""#);
        assert!(x_forwarded_proto.is_ok());
        let x_forwarded_proto = x_forwarded_proto.unwrap().1;
        assert_eq!(x_forwarded_proto, XForwardedProto::HTTPS);
    }

    #[test]
    fn test_parse_vcap_request_id() {
        let vcap_request_id = parse_vcap_request_id(r#"vcap_request_id:"e1604ad1-002c-48ff-6c44-f360e3096911""#);
        assert!(vcap_request_id.is_ok());
        let vcap_request_id = vcap_request_id.unwrap().1;
        assert_eq!(vcap_request_id, "e1604ad1-002c-48ff-6c44-f360e3096911");
    }

    #[test]
    fn test_parse_response_time() {
        let response_time = parse_response_time(r#"response_time:0.007799583"#);
        assert!(response_time.is_ok());
        let response_time = response_time.unwrap().1;
        assert_eq!(response_time, 0.007799583);
    }

    #[test]
    fn test_parse_app_id() {
        let app_id = parse_app_id(r#"app_id:"2c3f3955-d0cd-444c-9350-3fc47bd44eaa""#);
        assert!(app_id.is_ok());
        let app_id = app_id.unwrap().1;
        assert!(app_id.is_some());
        let app_id = app_id.unwrap();
        assert_eq!(app_id, "2c3f3955-d0cd-444c-9350-3fc47bd44eaa");

        let app_id = parse_app_id(r#"app_id:"-""#);
        assert!(app_id.is_ok());
        let app_id = app_id.unwrap().1;
        assert!(app_id.is_none());
    }

    #[test]
    fn test_parse_app_index() {
        let app_index = parse_app_index(r#"app_index:"0""#);
        assert!(app_index.is_ok());
        let app_index = app_index.unwrap().1;
        assert!(app_index.is_some());
        let app_index = app_index.unwrap();
        assert_eq!(app_index, 0);

        let app_index = parse_app_index(r#"app_index:"-""#);
        assert!(app_index.is_ok());
        let app_index = app_index.unwrap().1;
        assert!(app_index.is_none());
    }

    #[test]
    fn test_parse_trace_id() {
        let trace_id = parse_trace_id(r#"x_b3_traceid:"f7a79a16ab5c8383""#);
        assert!(trace_id.is_ok());
        let trace_id = trace_id.unwrap().1;
        assert!(trace_id.is_some());
        let trace_id = trace_id.unwrap();
        assert_eq!(trace_id, "f7a79a16ab5c8383");

        let trace_id = parse_trace_id(r#"x_b3_traceid:"-""#);
        assert!(trace_id.is_ok());
        let trace_id = trace_id.unwrap().1;
        assert!(trace_id.is_none());

        let trace_id = parse_trace_id(r#""#);
        print!("{:#?}", trace_id);
        assert!(trace_id.is_ok());
        let trace_id = trace_id.unwrap().1;
        assert!(trace_id.is_none());
    }

    #[test]
    fn test_parse_span_id() {
        let span_id = parse_span_id(r#"x_b3_spanid:"f7a79a16ab5c8383""#);
        assert!(span_id.is_ok());
        let span_id = span_id.unwrap().1;
        assert!(span_id.is_some());
        let span_id = span_id.unwrap();
        assert_eq!(span_id, "f7a79a16ab5c8383");

        let span_id = parse_span_id(r#"x_b3_spanid:"-""#);
        assert!(span_id.is_ok());
        let span_id = span_id.unwrap().1;
        assert!(span_id.is_none());

        let span_id = parse_span_id(r#""#);
        print!("{:#?}", span_id);
        assert!(span_id.is_ok());
        let span_id = span_id.unwrap().1;
        assert!(span_id.is_none());
    }

    #[test]
    fn test_parse_parent_span_id() {
        let parent_span_id = parse_parent_span_id(r#"x_b3_parentspanid:"f7a79a16ab5c8383""#);
        assert!(parent_span_id.is_ok());
        let parent_span_id = parent_span_id.unwrap().1;
        assert!(parent_span_id.is_some());
        let parent_span_id = parent_span_id.unwrap();
        assert_eq!(parent_span_id, "f7a79a16ab5c8383");

        let parent_span_id = parse_parent_span_id(r#"x_b3_parentspanid:"-""#);
        assert!(parent_span_id.is_ok());
        let parent_span_id = parent_span_id.unwrap().1;
        assert!(parent_span_id.is_none());

        let parent_span_id = parse_parent_span_id(r#""#);
        print!("{:#?}", parent_span_id);
        assert!(parent_span_id.is_ok());
        let parent_span_id = parent_span_id.unwrap().1;
        assert!(parent_span_id.is_none());
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
    fn test_parse_combined_log_entry() {
        let entry = parse_combined_log(r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)""#);
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
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "Mozilla/4.08 [en] (Win98; I ;Nav)");
    }

    #[test]
    fn test_parse_combined_log_entry_more() {
        let entry = parse_combined_log(r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1""#);
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
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "curl/7.52.1");
    }

    #[test]
    fn test_parse_gorouter_access_log() {
        let entry = parse_gorouter_log(r#"service.apps-domain.example.com - [2019-01-28T22:15:02.499+0000] "GET /v1/some/resource HTTP/1.1" 200 0 16409 "-" "Apache-HttpClient/4.3.3 (java 1.5)" "10.224.16.182:63326" "10.224.28.75:61022" x_forwarded_for:"10.178.177.71, 10.179.113.67, 10.224.16.182" x_forwarded_proto:"https" vcap_request_id:"e1604ad1-002c-48ff-6c44-f360e3096911" response_time:0.007799583 app_id:"2c3f3955-d0cd-444c-9350-3fc47bd44eaa" app_index:"0" x_b3_traceid:"f7a79a16ab5c8383" x_b3_spanid:"f7a79a16ab5c8383" x_b3_parentspanid:"-""#);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.request_host, "service.apps-domain.example.com");
        assert_eq!(entry.timestamp, FixedOffset::west(0).ymd(2019, 1, 28).and_hms_milli(22, 15, 2, 499));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/v1/some/resource");
        assert_eq!(entry.request.version(), http::Version::HTTP_11);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes_received, 0);
        assert_eq!(entry.bytes_sent, 16409);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "Apache-HttpClient/4.3.3 (java 1.5)");
        assert_eq!(entry.remote_addr, IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182)));
        assert_eq!(entry.remote_port, 63326);
        assert_eq!(entry.backend_addr, Some(IpAddr::V4(Ipv4Addr::new(10, 224, 28, 75))));
        assert_eq!(entry.backend_port, Some(61022));
        assert_eq!(entry.x_forwarded_for.len(), 3);
        assert_eq!(entry.x_forwarded_for[0], IpAddr::V4(Ipv4Addr::new(10, 178, 177, 71)));
        assert_eq!(entry.x_forwarded_for[1], IpAddr::V4(Ipv4Addr::new(10, 179, 113, 67)));
        assert_eq!(entry.x_forwarded_for[2], IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182)));
        assert_eq!(entry.x_forwarded_proto, XForwardedProto::HTTPS);
        assert_eq!(entry.vcap_request_id, "e1604ad1-002c-48ff-6c44-f360e3096911");
        assert_eq!(entry.response_time, 0.007799583);
        assert!(entry.app_id.is_some());
        assert_eq!(entry.app_id.unwrap(), "2c3f3955-d0cd-444c-9350-3fc47bd44eaa");
        assert!(entry.app_index.is_some());
        assert_eq!(entry.app_index.unwrap(), 0);
        assert!(entry.trace_id.is_some());
        assert_eq!(entry.trace_id.unwrap(), "f7a79a16ab5c8383");
        assert!(entry.span_id.is_some());
        assert_eq!(entry.span_id.unwrap(), "f7a79a16ab5c8383");
        assert!(entry.parent_span_id.is_none());
    }

    #[test]
    fn test_parse_gorouter_access_log_without_zipkin_info() {
        let entry = parse_gorouter_log(r#"service.apps-domain.example.com - [2019-01-28T22:15:02.499+0000] "GET /v1/some/resource HTTP/1.1" 200 0 16409 "-" "Apache-HttpClient/4.3.3 (java 1.5)" "10.224.16.182:63326" "10.224.28.75:61022" x_forwarded_for:"10.178.177.71, 10.179.113.67, 10.224.16.182" x_forwarded_proto:"https" vcap_request_id:"e1604ad1-002c-48ff-6c44-f360e3096911" response_time:0.007799583 app_id:"2c3f3955-d0cd-444c-9350-3fc47bd44eaa" app_index:"0" "#);
        print!("{:#?}", entry);
        assert!(entry.is_ok());
        let entry = entry.unwrap().1;
        assert_eq!(entry.request_host, "service.apps-domain.example.com");
        assert_eq!(entry.timestamp, FixedOffset::west(0).ymd(2019, 1, 28).and_hms_milli(22, 15, 2, 499));
        assert_eq!(entry.request.method(), http::Method::GET);
        assert_eq!(entry.request.uri(), "/v1/some/resource");
        assert_eq!(entry.request.version(), http::Version::HTTP_11);
        assert_eq!(entry.status_code, http::StatusCode::OK);
        assert_eq!(entry.bytes_received, 0);
        assert_eq!(entry.bytes_sent, 16409);
        assert!(entry.referrer.is_none());
        assert!(entry.user_agent.is_some());
        assert_eq!(entry.user_agent.unwrap(), "Apache-HttpClient/4.3.3 (java 1.5)");
        assert_eq!(entry.remote_addr, IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182)));
        assert_eq!(entry.remote_port, 63326);
        assert_eq!(entry.backend_addr, Some(IpAddr::V4(Ipv4Addr::new(10, 224, 28, 75))));
        assert_eq!(entry.backend_port, Some(61022));
        assert_eq!(entry.x_forwarded_for.len(), 3);
        assert_eq!(entry.x_forwarded_for[0], IpAddr::V4(Ipv4Addr::new(10, 178, 177, 71)));
        assert_eq!(entry.x_forwarded_for[1], IpAddr::V4(Ipv4Addr::new(10, 179, 113, 67)));
        assert_eq!(entry.x_forwarded_for[2], IpAddr::V4(Ipv4Addr::new(10, 224, 16, 182)));
        assert_eq!(entry.x_forwarded_proto, XForwardedProto::HTTPS);
        assert_eq!(entry.vcap_request_id, "e1604ad1-002c-48ff-6c44-f360e3096911");
        assert_eq!(entry.response_time, 0.007799583);
        assert!(entry.app_id.is_some());
        assert_eq!(entry.app_id.unwrap(), "2c3f3955-d0cd-444c-9350-3fc47bd44eaa");
        assert!(entry.app_index.is_some());
        assert_eq!(entry.app_index.unwrap(), 0);
        assert!(entry.trace_id.is_none());
        assert!(entry.span_id.is_none());
        assert!(entry.parent_span_id.is_none());
    }
}