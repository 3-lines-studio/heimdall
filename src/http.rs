use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

pub const MAX_BODY: usize = 1024 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub too_large: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        for part in self.header("cookie")?.split(';') {
            if let Some((key, value)) = part.trim().split_once('=') {
                if key == name {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn field(&self, name: &str) -> Option<String> {
        self.json()?.get(name)?.as_str().map(str::to_string)
    }

    pub fn number(&self, name: &str) -> Option<i64> {
        self.json()?.get(name)?.as_i64()
    }

    pub fn flag(&self, name: &str) -> bool {
        self.json()
            .and_then(|json| json.get(name).and_then(|value| value.as_bool()))
            .unwrap_or(false)
    }

    pub fn list(&self, name: &str) -> Option<Vec<String>> {
        let values = self.json()?.get(name)?.as_array()?.clone();
        Some(
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect(),
        )
    }
}

pub fn read(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.trim_end().split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_pairs(query)),
        None => (target, HashMap::new()),
    };
    let mut headers = HashMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let too_large = length > MAX_BODY;
    let mut body = vec![0u8; if too_large { 0 } else { length }];
    if !too_large && length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body,
        too_large,
    }))
}

pub fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        reason(status),
        body.len()
    )?;
    if !extra
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
    {
        stream.write_all(b"Cache-Control: no-store\r\n")?;
    }
    stream.write_all(b"Connection: close\r\n")?;
    for (name, value) in extra {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}

pub fn send_json(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    respond(stream, status, "application/json", &[], &body)
}

pub fn send_error(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    send_json(stream, status, &serde_json::json!({ "error": message }))
}

pub fn send_json_with(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    respond(stream, status, "application/json", extra, &body)
}

pub fn send_text(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    text: &str,
) -> std::io::Result<()> {
    respond(stream, status, content_type, &[], text.as_bytes())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

pub fn parse_pairs(input: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(key), percent_decode(value));
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            if let Some(byte) = hex {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_escapes_and_plus() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%2Ftmp"), "/tmp");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn parse_pairs_splits_on_ampersand() {
        let pairs = parse_pairs("project=bifrost&env=dev");
        assert_eq!(pairs.get("project").unwrap(), "bifrost");
        assert_eq!(pairs.get("env").unwrap(), "dev");
    }

    #[test]
    fn cookie_reads_one_value() {
        let request = Request {
            method: "GET".into(),
            path: "/".into(),
            query: HashMap::new(),
            headers: HashMap::from([(
                "cookie".to_string(),
                "a=1; heimdall_session=abc; b=2".to_string(),
            )]),
            body: Vec::new(),
            too_large: false,
        };
        assert_eq!(request.cookie("heimdall_session"), Some("abc".to_string()));
        assert_eq!(request.cookie("otra"), None);
    }

    #[test]
    fn bearer_reads_the_token() {
        let request = Request {
            method: "GET".into(),
            path: "/".into(),
            query: HashMap::new(),
            headers: HashMap::from([("authorization".to_string(), "Bearer hd_abc".to_string())]),
            body: Vec::new(),
            too_large: false,
        };
        assert_eq!(request.bearer(), Some("hd_abc"));
    }
}
