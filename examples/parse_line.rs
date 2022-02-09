use access_log_parser::{parse, AccessLogError, LogType};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Successful parse:");
    let entry = parse(
        LogType::CommonLog,
        r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] "GET / HTTP/1.1" 200 612"#,
    )?;
    println!("{:#?}", entry);

    println!();
    println!("Failure parse");
    let entry = parse(
        LogType::CommonLog,
        r#"127.0.0.1 - - [15/Mar/2019:03:17:05 +0000] HTTP/1.1" 200 612"#,
    );
    let AccessLogError::ParseError { msg } = entry.unwrap_err();
    println!("Error: {}", msg);
    Ok(())
}
