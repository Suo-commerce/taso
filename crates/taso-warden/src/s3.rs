//! An [`ObjectStore`] over S3: Garage in Phase 1 (v1.0 §3).
//!
//! Path-style requests (`<endpoint>/<bucket>/<key>`), signed with AWS
//! Signature Version 4.  Garage accepts both; path style needs no DNS.
//!
//! # Integrity
//!
//! Every PUT is signed over the SHA-256 of its body
//! (`x-amz-content-sha256`), and Garage refuses a body that does not match
//! it; the same digest goes in `x-amz-checksum-sha256`, so Garage keeps it
//! with the object.  A pack is also verified end to end on read
//! ([`crate::pack`]), so the store is not trusted for content either way:
//! the checksum turns a corrupted upload into a failed put instead of a
//! pack that fails later.
//!
//! # Limits (Phase 1)
//!
//! - A put reads the whole body into memory to hash it before sending.
//!   Packs are small (a Template's full stream ~1 MB, a Vessel's
//!   incremental a few KB); multipart upload comes when they are not.
//! - HTTP or HTTPS.  `http://` is for Garage on the node's private
//!   network.  `https://` verifies the server against the public web roots,
//!   or, with [`S3Config::ca_file`], against that CA alone (a Garage behind
//!   a proxy with a private CA).
//! - One attempt per request; the callers decide about retrying (a failed
//!   publish is retried by the next one).

use std::fmt::Write as _;
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::ship::{valid_key, ByteStream, ObjectStore};

/// Where the bucket is and how to sign for it.
#[derive(Clone)]
pub struct S3Config {
    /// `http://host[:port]` or `https://host[:port]`, no trailing slash.
    pub endpoint: String,
    /// The region the store expects in signatures (`garage` by default).
    pub region: String,
    /// The bucket.
    pub bucket: String,
    /// The access key id.
    pub access_key_id: String,
    /// The secret key.
    pub secret_key: String,
    /// For `https://`: trust only the CA certificates in this PEM file
    /// instead of the public web roots.
    pub ca_file: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret_key", &"<hidden>")
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

/// An [`ObjectStore`] in an S3 bucket.
#[derive(Debug)]
pub struct S3Store {
    config: S3Config,
    host: String,
    agent: ureq::Agent,
}

impl S3Store {
    /// A store over `config`.  Requests time out after `timeout`.
    pub fn new(config: S3Config, timeout: Duration) -> io::Result<Self> {
        let bad_endpoint = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "endpoint {:?} must be http://host[:port] or https://host[:port]",
                    config.endpoint
                ),
            )
        };
        let (tls, rest) = match (
            config.endpoint.strip_prefix("https://"),
            config.endpoint.strip_prefix("http://"),
        ) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            (None, None) => return Err(bad_endpoint()),
        };
        if rest.is_empty() || rest.contains('/') {
            return Err(bad_endpoint());
        }
        let host = rest.to_string();
        if config.ca_file.is_some() && !tls {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a CA file needs an https:// endpoint",
            ));
        }
        if config.bucket.is_empty()
            || !config
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid bucket name {:?}", config.bucket),
            ));
        }
        let mut agent = ureq::AgentBuilder::new().timeout(timeout);
        if let Some(ca) = &config.ca_file {
            agent = agent.tls_config(std::sync::Arc::new(tls_trusting(ca)?));
        }
        Ok(Self {
            config,
            host,
            agent: agent.build(),
        })
    }

    fn path(&self, key: &str) -> String {
        format!("/{}/{}", self.config.bucket, key)
    }

    /// A signed request for `method` on `path` with `query` (unencoded
    /// pairs) and `payload_hash`, plus extra signed headers.
    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        payload_hash: &str,
        extra: &[(&str, String)],
    ) -> ureq::Request {
        let amz_date = amz_date(SystemTime::now());
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), self.host.clone()),
            ("x-amz-content-sha256".into(), payload_hash.to_string()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        headers.extend(
            extra
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.clone())),
        );
        let auth = authorization(
            &self.config,
            method,
            path,
            query,
            &headers,
            payload_hash,
            &amz_date,
        );
        let mut url = format!("{}{}", self.config.endpoint, uri_encode(path, false));
        if !query.is_empty() {
            url.push('?');
            url.push_str(&canonical_query(query));
        }
        let mut req = self.agent.request(method, &url).set("authorization", &auth);
        for (k, v) in &headers {
            if k != "host" {
                req = req.set(k, v);
            }
        }
        req
    }
}

/// A TLS client configuration that trusts exactly the CA certificates in
/// the PEM file `ca`.
pub(crate) fn tls_trusting(ca: &std::path::Path) -> io::Result<rustls::ClientConfig> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;
    let bad = |why: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CA file {}: {why}", ca.display()),
        )
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca).map_err(|e| bad(e.to_string()))? {
        roots
            .add(cert.map_err(|e| bad(e.to_string()))?)
            .map_err(|e| bad(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(bad("no certificate in it".into()));
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| bad(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn bad_key(key: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid object key {key:?}"),
    )
}

/// A failed request as an `io::Error`, with the store's answer.
fn http_error(what: &str, e: ureq::Error) -> io::Error {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let code_text = between(&body, "<Code>", "</Code>").unwrap_or_default();
            io::Error::other(format!("{what}: HTTP {code} {code_text}"))
        }
        ureq::Error::Transport(t) => {
            io::Error::new(io::ErrorKind::ConnectionAborted, format!("{what}: {t}"))
        }
    }
}

impl ObjectStore for S3Store {
    fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        let mut body = Vec::new();
        data.read_to_end(&mut body)?;
        let digest = Sha256::digest(&body);
        let hash = hex(&digest);
        let extra = [("x-amz-checksum-sha256", base64(&digest))];
        self.request("PUT", &self.path(key), &[], &hash, &extra)
            .send_bytes(&body)
            .map_err(|e| http_error(&format!("put {key}"), e))?;
        Ok(body.len() as u64)
    }

    fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        match self
            .request("GET", &self.path(key), &[], EMPTY_SHA256, &[])
            .call()
        {
            Ok(resp) => Ok(Some(Box::new(resp.into_reader()))),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(http_error(&format!("get {key}"), e)),
        }
    }

    fn exists(&self, key: &str) -> io::Result<bool> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        match self
            .request("HEAD", &self.path(key), &[], EMPTY_SHA256, &[])
            .call()
        {
            Ok(_) => Ok(true),
            Err(ureq::Error::Status(404, _)) => Ok(false),
            Err(e) => Err(http_error(&format!("head {key}"), e)),
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        if !valid_key(prefix) {
            return Err(bad_key(prefix));
        }
        let dir = format!("{prefix}/");
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("list-type", "2"), ("prefix", dir.as_str())];
            if let Some(t) = &token {
                query.push(("continuation-token", t.as_str()));
            }
            let path = format!("/{}", self.config.bucket);
            let body = self
                .request("GET", &path, &query, EMPTY_SHA256, &[])
                .call()
                .map_err(|e| http_error(&format!("list {prefix}"), e))?
                .into_string()?;
            let page = parse_list(&body)?;
            keys.extend(
                page.keys
                    .into_iter()
                    .filter(|k| k.starts_with(&dir) && valid_key(k)),
            );
            match page.next {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        keys.sort();
        Ok(keys)
    }
}

// ── ListObjectsV2 ───────────────────────────────────────────────────

struct Page {
    keys: Vec<String>,
    next: Option<String>,
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let end = s[start..].find(close)? + start;
    Some(&s[start..end])
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The keys and the continuation token of one `ListObjectsV2` page.  Keys
/// are only ever `[A-Za-z0-9._/-]` (checked by the caller), so nothing in
/// them needs unescaping; the token may.
fn parse_list(body: &str) -> io::Result<Page> {
    if !body.contains("<ListBucketResult") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a ListBucketResult",
        ));
    }
    let mut keys = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find("<Contents>") {
        let tail = &rest[i..];
        let end = tail
            .find("</Contents>")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unclosed <Contents>"))?;
        let item = &tail[..end];
        let key = between(item, "<Key>", "</Key>").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "a <Contents> without <Key>")
        })?;
        keys.push(xml_unescape(key));
        rest = &tail[end..];
    }
    let truncated = between(body, "<IsTruncated>", "</IsTruncated>") == Some("true");
    let next = if truncated {
        Some(xml_unescape(
            between(body, "<NextContinuationToken>", "</NextContinuationToken>").ok_or_else(
                || {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated without a continuation token",
                    )
                },
            )?,
        ))
    } else {
        None
    };
    Ok(Page { keys, next })
}

// ── Signature Version 4 ─────────────────────────────────────────────

/// SHA-256 of the empty body.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &x)| n | (u32::from(x) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// RFC 3986 encoding as SigV4 wants it: unreserved characters kept, `/`
/// kept in paths (`slash == false`), everything else `%XX`.
fn uri_encode(s: &str, slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (b == b'/' && !slash)
        {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `YYYYMMDDTHHMMSSZ` in UTC.
fn amz_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The `Authorization` header for a request.  `headers` are lowercase
/// names and must include `host` and `x-amz-date`; all of them are
/// signed.
fn authorization(
    c: &S3Config,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(String, String)],
    payload_hash: &str,
    amz_date: &str,
) -> String {
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    hs.sort();
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed: String = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed}\n{payload_hash}",
        uri_encode(path, false),
        canonical_query(query)
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", c.region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let k = hmac(format!("AWS4{}", c.secret_key).as_bytes(), date.as_bytes());
    let k = hmac(&k, c.region.as_bytes());
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let signature = hex(&hmac(&k, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        c.access_key_id
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn aws_example() -> S3Config {
        S3Config {
            endpoint: "http://examplebucket.s3.amazonaws.com".into(),
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ca_file: None,
        }
    }

    /// The "GET Object" example of AWS's Signature Version 4 documentation
    /// (virtual-host style, so the path is the key alone).
    #[test]
    fn signs_the_aws_documentation_example() {
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), EMPTY_SHA256.to_string()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let auth = authorization(
            &aws_example(),
            "GET",
            "/test.txt",
            &[],
            &headers,
            EMPTY_SHA256,
            "20130524T000000Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn dates_are_utc_civil() {
        let at = |s: u64| amz_date(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "19700101T000000Z");
        assert_eq!(at(1_369_353_600), "20130524T000000Z");
        assert_eq!(at(951_782_400), "20000229T000000Z", "a leap day");
        assert_eq!(at(1_791_158_399), "20261004T235959Z");
    }

    #[test]
    fn encodings() {
        assert_eq!(uri_encode("/b/pack/a-b_c.d~", false), "/b/pack/a-b_c.d~");
        assert_eq!(
            uri_encode("vessels/ab/pack/", true),
            "vessels%2Fab%2Fpack%2F"
        );
        assert_eq!(uri_encode("a b+c", false), "a%20b%2Bc");
        assert_eq!(
            canonical_query(&[("prefix", "x/"), ("list-type", "2")]),
            "list-type=2&prefix=x%2F"
        );
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(hex(&Sha256::digest(b"")), EMPTY_SHA256);
    }

    #[test]
    fn list_pages_parse() {
        let page = parse_list(
            "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>true</IsTruncated>\
             <Contents><Key>v/a/pack/1</Key><Size>3</Size></Contents>\
             <Contents><Key>v/a/pack/2</Key></Contents>\
             <NextContinuationToken>tok&amp;en</NextContinuationToken></ListBucketResult>",
        )
        .unwrap();
        assert_eq!(page.keys, vec!["v/a/pack/1", "v/a/pack/2"]);
        assert_eq!(page.next.as_deref(), Some("tok&en"));
        let last =
            parse_list("<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>")
                .unwrap();
        assert!(last.keys.is_empty() && last.next.is_none());
        assert!(parse_list("<Error><Code>AccessDenied</Code></Error>").is_err());
        assert!(
            parse_list("<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>")
                .is_err()
        );
        assert!(parse_list(
            "<ListBucketResult><Contents><Size>1</Size></Contents></ListBucketResult>"
        )
        .is_err());
    }

    #[test]
    fn bad_endpoints_and_buckets_are_refused() {
        let ok = S3Config {
            endpoint: "http://127.0.0.1:3900".into(),
            region: "garage".into(),
            bucket: "taso".into(),
            ..aws_example()
        };
        assert!(S3Store::new(ok.clone(), Duration::from_secs(1)).is_ok());
        assert!(S3Store::new(
            S3Config {
                endpoint: "https://garage.example:3900".into(),
                ..ok.clone()
            },
            Duration::from_secs(1)
        )
        .is_ok());
        assert!(
            S3Store::new(
                S3Config {
                    ca_file: Some("/nonexistent.pem".into()),
                    ..ok.clone()
                },
                Duration::from_secs(1)
            )
            .is_err(),
            "a CA file with http://"
        );
        for endpoint in [
            "ftp://x",
            "127.0.0.1:3900",
            "http://",
            "https://",
            "http://h/path",
        ] {
            assert!(
                S3Store::new(
                    S3Config {
                        endpoint: endpoint.into(),
                        ..ok.clone()
                    },
                    Duration::from_secs(1)
                )
                .is_err(),
                "{endpoint}"
            );
        }
        for bucket in ["", "Taso", "a/b"] {
            assert!(
                S3Store::new(
                    S3Config {
                        bucket: bucket.into(),
                        ..ok.clone()
                    },
                    Duration::from_secs(1)
                )
                .is_err(),
                "{bucket}"
            );
        }
        assert!(
            !format!("{ok:?}").contains("EXAMPLEKEY"),
            "the secret is never printed"
        );
    }

    /// HTTPS against a local server whose certificate is signed by a
    /// private CA: trusted with that CA as `ca_file`, refused without it
    /// (the public roots do not know it) and with another CA.  Skipped if
    /// `openssl` or `python3` is missing.
    #[test]
    fn https_trusts_exactly_the_given_ca() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        // Every HEAD is answered 404 (the key does not exist).
        let srv = TestServer::start(
            true,
            r#"
class H(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
"#,
        );
        let store = |ca: Option<&str>| {
            S3Store::new(
                S3Config {
                    endpoint: format!("https://localhost:{}", srv.port),
                    region: "garage".into(),
                    bucket: "taso".into(),
                    ca_file: ca.map(|c| srv.dir.path().join(c)),
                    ..aws_example()
                },
                Duration::from_secs(5),
            )
            .unwrap()
        };
        assert!(
            !store(Some("ca.pem")).exists("a/b").unwrap(),
            "with its CA: a 404 answer, so the key does not exist"
        );
        assert!(
            store(None).exists("a/b").is_err(),
            "the public roots do not know a private CA"
        );
        assert!(
            store(Some("other.pem")).exists("a/b").is_err(),
            "another CA is not trusted"
        );
        let empty = srv.dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        assert!(
            tls_trusting(&empty).is_err(),
            "a CA file with no certificate"
        );
    }

    /// PUT, GET, HEAD and a paged list against a local S3 stand-in (plain
    /// HTTP), and the store's error answers: a missing key is `None` /
    /// `false`, a refusal carries the store's `<Code>`, and the payload
    /// hash header matches the body.  What the ignored Garage test checks
    /// against a real store, here on every run.
    #[test]
    fn talks_s3_to_a_local_server() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = TestServer::start(
            false,
            r#"
import hashlib, urllib.parse
objs = {}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def reply(self, code, body=b"", ctype="application/xml"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def error(self, code, name):
        self.reply(code, ("<Error><Code>%s</Code><Message>m</Message></Error>" % name).encode())
    def key(self):
        u = urllib.parse.urlparse(self.path)
        parts = urllib.parse.unquote(u.path).split("/", 2)
        return parts[1], (parts[2] if len(parts) > 2 else ""), urllib.parse.parse_qs(u.query)
    def signed(self):
        a = self.headers.get("authorization", "")
        return a.startswith("AWS4-HMAC-SHA256 Credential=") and self.headers.get("x-amz-date")
    def do_PUT(self):
        b, k, _ = self.key()
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if not self.signed(): return self.error(403, "AccessDenied")
        if k.startswith("deny/"): return self.error(403, "AccessDenied")
        if self.headers.get("x-amz-content-sha256") != hashlib.sha256(body).hexdigest():
            return self.error(400, "XAmzContentSHA256Mismatch")
        objs[k] = body
        self.reply(200)
    def do_HEAD(self):
        b, k, _ = self.key()
        self.reply(200 if k in objs else 404)
    def do_GET(self):
        b, k, q = self.key()
        if k == "" and q.get("list-type") == ["2"]:
            prefix = q.get("prefix", [""])[0]
            keys = sorted(x for x in objs if x.startswith(prefix))
            start = int(q.get("continuation-token", ["0"])[0])
            page = keys[start:start + 2]
            more = start + 2 < len(keys)
            xml = "<ListBucketResult>" + "".join("<Contents><Key>%s</Key></Contents>" % x for x in page)
            xml += "<IsTruncated>%s</IsTruncated>" % ("true" if more else "false")
            if more: xml += "<NextContinuationToken>%d</NextContinuationToken>" % (start + 2)
            return self.reply(200, (xml + "</ListBucketResult>").encode())
        if k not in objs: return self.error(404, "NoSuchKey")
        self.reply(200, objs[k], "application/octet-stream")
    def log_message(self, *a): pass
"#,
        );
        let store = S3Store::new(
            S3Config {
                endpoint: format!("http://127.0.0.1:{}", srv.port),
                region: "garage".into(),
                bucket: "taso".into(),
                ..aws_example()
            },
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(!store.exists("d/a").unwrap(), "missing: false");
        assert!(store.get("d/a").unwrap().is_none(), "missing: None");
        assert_eq!(store.put("d/a", &mut &b"hello"[..]).unwrap(), 5);
        let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        store.put("d/sub/b", &mut &big[..]).unwrap();
        store.put("d/c", &mut &b""[..]).unwrap();
        assert!(store.exists("d/a").unwrap());
        let mut got = Vec::new();
        store
            .get("d/sub/b")
            .unwrap()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, big, "a large object, read back whole");
        assert_eq!(
            store.list("d").unwrap(),
            vec!["d/a".to_string(), "d/c".into(), "d/sub/b".into()],
            "three keys over two pages"
        );
        let e = store.put("deny/x", &mut &b"x"[..]).unwrap_err();
        assert!(
            e.to_string().contains("HTTP 403 AccessDenied"),
            "the store's code is reported: {e}"
        );
        drop(srv);
        assert_eq!(
            store.exists("d/a").unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted,
            "no server: a transport error"
        );
    }
    /// The same contract tests as `LocalStore`, against a real Garage:
    /// set TASO_S3_ENDPOINT, TASO_S3_BUCKET, TASO_S3_KEY_ID, TASO_S3_SECRET
    /// (TASO_S3_REGION defaults to `garage`).
    #[test]
    #[ignore = "needs a Garage bucket: set TASO_S3_*"]
    fn round_trip_on_garage() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let store = S3Store::new(
            S3Config {
                endpoint: env("TASO_S3_ENDPOINT"),
                region: std::env::var("TASO_S3_REGION").unwrap_or_else(|_| "garage".into()),
                bucket: env("TASO_S3_BUCKET"),
                access_key_id: env("TASO_S3_KEY_ID"),
                secret_key: env("TASO_S3_SECRET"),
                ca_file: std::env::var_os("TASO_S3_CA").map(Into::into),
            },
            Duration::from_secs(10),
        )
        .unwrap();
        let dir = format!("t-{}", std::process::id());
        let k = |n: &str| format!("{dir}/{n}");
        assert!(!store.exists(&k("a")).unwrap());
        assert!(store.get(&k("a")).unwrap().is_none());
        assert_eq!(store.list(&dir).unwrap(), Vec::<String>::new());
        assert_eq!(store.put(&k("a"), &mut &b"hello"[..]).unwrap(), 5);
        let big: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
        store.put(&k("sub/b"), &mut &big[..]).unwrap();
        assert!(store.exists(&k("a")).unwrap());
        let mut got = Vec::new();
        store
            .get(&k("sub/b"))
            .unwrap()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, big);
        store.put(&k("a"), &mut &b"again"[..]).unwrap();
        let mut a = String::new();
        store
            .get(&k("a"))
            .unwrap()
            .unwrap()
            .read_to_string(&mut a)
            .unwrap();
        assert_eq!(a, "again");
        assert_eq!(store.list(&dir).unwrap(), vec![k("a"), k("sub/b")]);
        // More keys than one page (Garage pages at 1000).
        for i in 0..1005 {
            store
                .put(&k(&format!("many/{i:05}")), &mut &b"x"[..])
                .unwrap();
        }
        assert_eq!(store.list(&format!("{dir}/many")).unwrap().len(), 1005);
        assert!(store.put("../x", &mut &b""[..]).is_err());
        let wrong = S3Store::new(
            S3Config {
                secret_key: "wrong".into(),
                ..store.config.clone()
            },
            Duration::from_secs(10),
        )
        .unwrap();
        let e = wrong.put(&k("c"), &mut &b"x"[..]).unwrap_err();
        println!("a wrong secret: {e}");
        assert!(!store.exists(&k("c")).unwrap());
    }

    /// Whether the tools the local-server tests need are here.
    pub(crate) fn have_tools() -> bool {
        use std::process::{Command, Stdio};
        ["openssl", "python3"].iter().all(|c| {
            Command::new(c)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
        })
    }

    /// A local test server: Python's `http.server` with the handler class
    /// `H` given as source, on 127.0.0.1 and a free port.  With `tls`, it
    /// speaks HTTPS with a certificate for `localhost` and 127.0.0.1 signed
    /// by a private CA (`ca.pem` in `dir`); `other.pem` is a second,
    /// unrelated CA.  Stopped when dropped.
    pub(crate) struct TestServer {
        pub(crate) dir: tempfile::TempDir,
        pub(crate) port: u16,
        child: std::process::Child,
    }

    impl TestServer {
        pub(crate) fn start(tls: bool, handler: &str) -> Self {
            use std::process::{Command, Stdio};
            let dir = tempfile::tempdir().unwrap();
            let p = |n: &str| dir.path().join(n).to_string_lossy().into_owned();
            let sh = |args: &[&str]| {
                assert!(
                    Command::new("openssl")
                        .args(args)
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success(),
                    "{args:?}"
                )
            };
            let wrap = if tls {
                for ca in ["ca", "other"] {
                    sh(&[
                        "req",
                        "-x509",
                        "-newkey",
                        "ec",
                        "-pkeyopt",
                        "ec_paramgen_curve:P-256",
                        "-nodes",
                        "-days",
                        "2",
                        "-subj",
                        &format!("/CN=taso test {ca}"),
                        "-keyout",
                        &p(&format!("{ca}.key")),
                        "-out",
                        &p(&format!("{ca}.pem")),
                    ]);
                }
                sh(&[
                    "req",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                    "-keyout",
                    &p("srv.key"),
                    "-out",
                    &p("srv.csr"),
                ]);
                std::fs::write(p("ext"), "subjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
                sh(&[
                    "x509",
                    "-req",
                    "-in",
                    &p("srv.csr"),
                    "-CA",
                    &p("ca.pem"),
                    "-CAkey",
                    &p("ca.key"),
                    "-CAcreateserial",
                    "-days",
                    "2",
                    "-extfile",
                    &p("ext"),
                    "-out",
                    &p("srv.pem"),
                ]);
                format!(
                    "import ssl\nc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain({:?}, {:?})\ns.socket = c.wrap_socket(s.socket, server_side=True)\n",
                    p("srv.pem"),
                    p("srv.key")
                )
            } else {
                String::new()
            };
            let script = format!(
                "import http.server\n{handler}\ns = http.server.HTTPServer((\"127.0.0.1\", 0), H)\n{wrap}print(s.server_address[1], flush=True)\ns.serve_forever()\n"
            );
            let mut child = Command::new("python3")
                .args(["-c", &script])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut port = String::new();
            std::io::BufRead::read_line(
                &mut std::io::BufReader::new(child.stdout.as_mut().unwrap()),
                &mut port,
            )
            .unwrap();
            let port = port.trim().parse().unwrap_or_else(|_| {
                let _ = child.kill();
                panic!("the test server did not start: {port:?}")
            });
            Self { dir, port, child }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
