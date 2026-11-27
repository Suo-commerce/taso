//! An [`ObjectStore`] over S3: Garage in Phase 1 (v1.0 §3).
//!
//! Path-style requests (`<endpoint>/<bucket>/<key>`), signed with AWS
//! Signature Version 4.  Garage accepts both; path style needs no DNS.
//!
//! # Integrity
//!
//! Every PUT is signed over the SHA-256 of its body
//! (`x-amz-content-sha256`), and Garage refuses a body that does not match
//! it.  A whole-object PUT also sends the digest in `x-amz-checksum-sha256`,
//! so Garage keeps it with the object; the parts of a multipart upload
//! send only the signed digest (each part is refused if it does not match
//! its own), which every S3 store checks.  A pack is also verified end to
//! end on read ([`crate::pack`]), so the store is not trusted for content
//! either way.
//!
//! # Memory
//!
//! A put holds at most one part ([`PART`], 16 MiB) of the body: an object
//! that fits in one is sent with one PUT, a larger one as a multipart
//! upload, a part at a time (audit 2026-11-16, S3: the whole pack was read
//! into memory first, outside every agent's memory limit, and a pack over
//! S3's 5 GB single-PUT limit could not ship at all).  An upload that
//! fails is aborted, so its parts do not stay in the bucket.
//!
//! # Limits (Phase 1)
//!
//! - HTTP or HTTPS.  `http://` is for Garage on the node's private
//!   network.  `https://` verifies the server against the public web roots,
//!   or, with [`S3Config::ca_file`], against that CA alone (a Garage behind
//!   a proxy with a private CA).
//! - One attempt per request; the callers decide about retrying (a failed
//!   publish is retried by the next one).  The one exception is a
//!   download's later pieces (below).
//!
//! # Downloads
//!
//! A GET reads an object in pieces of [`PIECE`] (64 MiB), each its own
//! ranged request (the maturity review's finding 7; D&D 7-a…7-c,
//! 2026-11-27): one limit on the whole call cut every download that took
//! longer than 30 s, so a large Vessel could not be reborn from the store.
//! Each phase of a request has its own limit instead, and a piece's body
//! must arrive within [`PIECE_BODY`].
//!
//! - A piece that fails partway (the connection broken, its body too
//!   slow, a 5xx) is asked for again from the byte it reached, three more
//!   times, after 1, 2 and 4 s; each try is logged, and the last failure
//!   is a `FAILED` line and the read's error.  A first request that gets no
//!   answer at all is the caller's, as for every request.
//! - Every later piece is asked for with the first answer's ETag
//!   (`If-Match`), and its own answer's ETag is compared with it: an object
//!   changed or deleted while it was read ends the read at once, not
//!   retried, instead of joining the bytes of two objects.
//! - An object larger than one piece logs its progress: at the start,
//!   every 10 s, and at the end.
//! - A store that ignores `Range` answers the whole object to the first
//!   request, read as one answer (its body within [`PIECE_BODY`]); an empty
//!   object (which has no byte 0) is asked for again without a range.

use std::fmt::Write as _;
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::http;

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
    /// The operator's yes to an `http://` endpoint: data and signed
    /// requests cross the network unencrypted (review fix M4, Kimi's M4).
    /// Without it `http://` is refused; with `https://` it is a
    /// contradiction and refused too.
    pub plaintext: bool,
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
            .field("plaintext", &self.plaintext)
            .finish()
    }
}

/// How much of an object one GET asks for (finding 7, D&D 7-a,
/// 2026-11-27): a 10 GiB `fs` section is 160 requests.
pub const PIECE: u64 = 64 << 20;

/// How long one piece's body may take to arrive (D&D 7-a): 64 MiB in it
/// is about 0.5 MiB/s at the least.  Also how long one body may take to
/// send (a part is 16 MiB).
pub const PIECE_BODY: Duration = Duration::from_secs(120);

/// The waits before a failed piece is asked for again (D&D 7-c): three
/// more tries after the first.
const PIECE_WAITS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// A download's progress line at most this often.
const PROGRESS_EVERY: Duration = Duration::from_secs(10);

/// An [`ObjectStore`] in an S3 bucket.
#[derive(Debug)]
pub struct S3Store {
    conn: Conn,
    /// The bucket answered as there once: a HEAD's 404 is then the key's.
    bucket_seen: std::sync::atomic::AtomicBool,
    /// A download's piece ([`PIECE`]; smaller in tests).
    piece: u64,
    /// The waits before a piece is asked for again ([`PIECE_WAITS`]).
    waits: [Duration; 3],
    /// The limit of each phase of a request but a body's (kept for
    /// [`S3Store::tuned`]).
    #[cfg(test)]
    timeout: Duration,
}

/// What a request needs: where the store is, how to sign, the client.
/// A download's reader keeps its own copy, to ask for its later pieces.
#[derive(Clone, Debug)]
struct Conn {
    config: S3Config,
    host: String,
    agent: ureq::Agent,
}

impl S3Store {
    /// A store over `config`.  Each phase of a request (to connect, to
    /// send its head, to receive the answer's head) waits at most
    /// `timeout`; a body is sent, or a piece of one received, within
    /// [`PIECE_BODY`] (see the module docs).
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
        // Plain HTTP only when the operator said so (review fix M4).
        match (tls, config.plaintext) {
            (false, false) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "endpoint {:?} is plain http: the store's data and signed requests would cross the network unencrypted; use https://, or say \"plaintext\": true",
                        config.endpoint
                    ),
                ))
            }
            (true, true) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "\"plaintext\": true with an https:// endpoint",
                ))
            }
            (false, true) => eprintln!(
                "taso: the store {} is plain http (\"plaintext\": true): its data and signed requests cross the network unencrypted",
                config.endpoint
            ),
            (true, false) => {}
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
        let agent = s3_agent(timeout, PIECE_BODY, config.ca_file.as_deref())?;
        Ok(Self {
            conn: Conn {
                config,
                host,
                agent,
            },
            bucket_seen: Default::default(),
            piece: PIECE,
            waits: PIECE_WAITS,
            #[cfg(test)]
            timeout,
        })
    }

    /// Small pieces, a short body limit and short waits, for tests.
    #[cfg(test)]
    fn tuned(mut self, piece: u64, body: Duration, wait: Duration) -> Self {
        self.conn.agent =
            s3_agent(self.timeout, body, self.conn.config.ca_file.as_deref()).unwrap();
        self.piece = piece;
        self.waits = [wait; 3];
        self
    }

    fn path(&self, key: &str) -> String {
        format!("/{}/{}", self.conn.config.bucket, key)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        payload_hash: &str,
        extra: &[(&str, String)],
    ) -> http::request::Builder {
        self.conn.request(method, path, query, payload_hash, extra)
    }

    fn send(
        &self,
        what: &str,
        req: http::request::Builder,
        body: impl ureq::AsSendBody,
    ) -> io::Result<http::Response<ureq::Body>> {
        self.conn.send(what, req, body)
    }

    fn send_again<B: ureq::AsSendBody + Copy>(
        &self,
        what: &str,
        make: impl Fn() -> http::request::Builder,
        body: B,
    ) -> io::Result<http::Response<ureq::Body>> {
        self.conn.send_again(what, make, body)
    }
}

impl Conn {
    /// A signed request for `method` on `path` with `query` (unencoded
    /// pairs) and `payload_hash`, plus extra signed headers.
    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        payload_hash: &str,
        extra: &[(&str, String)],
    ) -> http::request::Builder {
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
        let mut req = http::Request::builder()
            .method(method)
            .uri(&url)
            .header("authorization", &auth);
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k, v);
            }
        }
        req
    }

    /// Send `req` with `body`.  Any answer is `Ok` (the caller reads the
    /// status); `Err` is a request that got no answer.
    fn send(
        &self,
        what: &str,
        req: http::request::Builder,
        body: impl ureq::AsSendBody,
    ) -> io::Result<http::Response<ureq::Body>> {
        let req = req
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{what}: {e}")))?;
        self.agent
            .run(req)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{what}: {e}")))
    }

    /// [`S3Store::send`] for a request that may be sent again: one whose
    /// effect is the same however often the store carries it out (a GET, a
    /// HEAD, a DELETE, a PUT of the same bytes under the same key or part
    /// number).  A system call interrupted by a signal is not a broken
    /// connection (a stopped and continued process gets `EINTR` from a
    /// socket call with a timeout even under `SA_RESTART`; see
    /// `taso_core::frame::read_frame`): the request `make` builds is sent
    /// again, on a new connection, up to [`INTERRUPTED_TRIES`] times.  It
    /// is built again each time, so its date is the try's own.
    fn send_again<B: ureq::AsSendBody + Copy>(
        &self,
        what: &str,
        make: impl Fn() -> http::request::Builder,
        body: B,
    ) -> io::Result<http::Response<ureq::Body>> {
        let mut interrupted = 0;
        loop {
            let req = make()
                .body(body)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{what}: {e}")))?;
            match self.agent.run(req) {
                Err(ureq::Error::Io(e))
                    if e.kind() == io::ErrorKind::Interrupted
                        && interrupted < INTERRUPTED_TRIES =>
                {
                    interrupted += 1;
                }
                other => {
                    return other.map_err(|e| {
                        io::Error::new(io::ErrorKind::ConnectionAborted, format!("{what}: {e}"))
                    })
                }
            }
        }
    }
}

/// How often a request interrupted by a signal is sent again before the
/// interruption is reported as its failure.
const INTERRUPTED_TRIES: u32 = 8;

/// The HTTP client for S3 (finding 7): each phase of a request has its
/// own limit, and none bounds the whole call (one limit on the whole call
/// cut every download that took longer).  `timeout` to resolve the name,
/// to connect (TLS included), to send a request's head and to receive an
/// answer's head; `body` to send a body or to receive one.  A GET receives
/// an object a piece at a time ([`PIECE`]), each its own request, so
/// `body` bounds one piece.  As [`http_agent`] otherwise.
fn s3_agent(
    timeout: Duration,
    body: Duration,
    ca: Option<&std::path::Path>,
) -> io::Result<ureq::Agent> {
    let mut config = ureq::Agent::config_builder()
        .timeout_resolve(Some(timeout))
        .timeout_connect(Some(timeout))
        .timeout_send_request(Some(timeout))
        .timeout_send_body(Some(body))
        .timeout_recv_response(Some(timeout))
        .timeout_recv_body(Some(body))
        .http_status_as_error(false);
    if let Some(ca) = ca {
        config = config.tls_config(tls_trusting(ca)?);
    }
    Ok(config.build().into())
}

/// The HTTP client for the Kubernetes API: every request times out after
/// `timeout`; with `ca`, TLS trusts exactly the certificates in that
/// file, else the public roots.  Every status is an answer, not an error
/// (`http_status_as_error(false)`): an error's body carries the server's
/// reason, which the callers report.
pub(crate) fn http_agent(
    timeout: Duration,
    ca: Option<&std::path::Path>,
) -> io::Result<ureq::Agent> {
    let mut config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false);
    if let Some(ca) = ca {
        config = config.tls_config(tls_trusting(ca)?);
    }
    Ok(config.build().into())
}

/// A TLS configuration that trusts exactly the CA certificates in the PEM
/// file `ca` (and not the public roots).
pub(crate) fn tls_trusting(ca: &std::path::Path) -> io::Result<ureq::tls::TlsConfig> {
    use ureq::tls::{parse_pem, PemItem, RootCerts, TlsConfig};
    let bad = |why: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CA file {}: {why}", ca.display()),
        )
    };
    let pem = std::fs::read(ca).map_err(|e| bad(e.to_string()))?;
    let mut certs = Vec::new();
    for item in parse_pem(&pem) {
        if let PemItem::Certificate(c) = item.map_err(|e| bad(e.to_string()))? {
            certs.push(c.to_owned());
        }
    }
    if certs.is_empty() {
        return Err(bad("no certificate in it".into()));
    }
    Ok(TlsConfig::builder()
        .root_certs(RootCerts::Specific(std::sync::Arc::new(certs)))
        .build())
}

fn bad_key(key: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid object key {key:?}"),
    )
}

fn no_bucket(what: &str, bucket: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{what}: the bucket {bucket:?} does not exist (NoSuchBucket): not an absent object"
        ),
    )
}

impl S3Store {
    /// `Ok` if the bucket is there (a HEAD of it answers 2xx), asked once
    /// in this store's life; an error if it answers 404 or anything else.
    fn bucket_is_there(&self, what: &str) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        if self.bucket_seen.load(Ordering::Relaxed) {
            return Ok(());
        }
        let path = format!("/{}", self.conn.config.bucket);
        let req = || self.request("HEAD", &path, &[], EMPTY_SHA256, &[]);
        let resp = self.send_again(what, req, ())?;
        if resp.status() == http::StatusCode::NOT_FOUND {
            return Err(no_bucket(what, &self.conn.config.bucket));
        }
        success(&format!("{what}: head the bucket"), resp)?;
        self.bucket_seen.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// The answer if it is a success (2xx), else an `io::Error` with the
/// status and the store's `<Code>`.
fn success(
    what: &str,
    mut resp: http::Response<ureq::Body>,
) -> io::Result<http::Response<ureq::Body>> {
    let code = resp.status().as_u16();
    if (200..300).contains(&code) {
        return Ok(resp);
    }
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    let code_text = between(&body, "<Code>", "</Code>").unwrap_or_default();
    Err(io::Error::other(format!("{what}: HTTP {code} {code_text}")))
}

impl S3Store {
    /// Every key under `prefix` with its raw `LastModified`, in key order,
    /// through every page of `ListObjectsV2`.
    fn list_pages(&self, prefix: &str) -> io::Result<Vec<(String, Option<String>)>> {
        if !valid_key(prefix) {
            return Err(bad_key(prefix));
        }
        let dir = format!("{prefix}/");
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        let mut pages = 0u32;
        loop {
            // An endpoint that repeats its continuation token, or never
            // runs out of them, would keep this loop going through
            // requests that each succeed; both are errors here, never a
            // listing cut short and handed back as complete.
            pages += 1;
            if pages > MAX_LIST_PAGES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("list {prefix}: more than {MAX_LIST_PAGES} pages; the endpoint does not finish"),
                ));
            }
            let mut query = vec![("list-type", "2"), ("prefix", dir.as_str())];
            if let Some(t) = &token {
                query.push(("continuation-token", t.as_str()));
            }
            let path = format!("/{}", self.conn.config.bucket);
            let what = format!("list {prefix}");
            let req = || self.request("GET", &path, &query, EMPTY_SHA256, &[]);
            let body = success(&what, self.send_again(&what, req, ())?)?
                .body_mut()
                .read_to_string()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {e}")))?;
            let page = parse_list(&body)?;
            keys.extend(
                page.keys
                    .into_iter()
                    .filter(|(k, _)| k.starts_with(&dir) && valid_key(k)),
            );
            match page.next {
                Some(t) if token.as_deref() == Some(t.as_str()) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("list {prefix}: the endpoint repeated its continuation token; the listing does not advance"),
                    ));
                }
                Some(t) => token = Some(t),
                None => break,
            }
        }
        keys.sort();
        Ok(keys)
    }
}

/// The most of a body a put holds: one part.  S3's parts are 5 MiB at
/// least (but the last) and 10,000 at most, so an object may be up to
/// about 156 GiB.
pub const PART: usize = 16 << 20;

/// S3's most parts in one upload.
const MAX_PARTS: u32 = 10_000;

/// The next part of `data` into `buf`: [`PART`] bytes, fewer only where
/// the body ends.  `buf` grows to what is read, so a small body costs
/// only its own size.
fn read_part(data: &mut dyn Read, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.clear();
    Read::take(&mut *data, PART as u64).read_to_end(buf)?;
    Ok(())
}

impl S3Store {
    /// One PUT of a body that fits in a part.
    fn put_whole(&self, key: &str, body: &[u8]) -> io::Result<u64> {
        let digest = Sha256::digest(body);
        let hash = hex(&digest);
        let extra = [("x-amz-checksum-sha256", base64(&digest))];
        let what = format!("put {key}");
        let req = || self.request("PUT", &self.path(key), &[], &hash, &extra);
        success(&what, self.send_again(&what, req, body)?)?;
        Ok(body.len() as u64)
    }

    /// A multipart upload of `first` (a full part) and the rest of
    /// `data`; aborted if any step fails.
    fn put_parts(&self, key: &str, first: Vec<u8>, data: &mut dyn Read) -> io::Result<u64> {
        let what = format!("put {key}");
        let path = self.path(key);
        // Sent once (also when interrupted): a second start would open a
        // second upload and leave the first one open.
        let req = self.request("POST", &path, &[("uploads", "")], EMPTY_SHA256, &[]);
        let start = format!("{what}: start a multipart upload");
        let body = success(&start, self.send(&start, req, ())?)?
            .body_mut()
            .read_to_string()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{start}: {e}")))?;
        let id = between(&body, "<UploadId>", "</UploadId>")
            .filter(|i| !i.is_empty())
            .map(xml_unescape)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{start}: no UploadId"))
            })?;
        let sent = self.upload_parts(&what, &path, &id, first, data);
        if sent.is_err() {
            // Best effort: an upload left open keeps its parts (and their
            // space) until the bucket's own lifecycle rule, if any, ends it.
            let req = || self.request("DELETE", &path, &[("uploadId", &id)], EMPTY_SHA256, &[]);
            match self.send_again(&what, req, ()) {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => eprintln!(
                    "taso: {what}: could not abort the multipart upload {id}: HTTP {}",
                    r.status().as_u16()
                ),
                Err(e) => eprintln!("taso: {what}: could not abort the multipart upload {id}: {e}"),
            }
        }
        sent
    }

    /// Every part, then the upload's completion.
    fn upload_parts(
        &self,
        what: &str,
        path: &str,
        id: &str,
        mut buf: Vec<u8>,
        data: &mut dyn Read,
    ) -> io::Result<u64> {
        let mut etags: Vec<String> = Vec::new();
        let mut total = 0u64;
        while !buf.is_empty() {
            let n = etags.len() as u32 + 1;
            if n > MAX_PARTS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{what}: more than {MAX_PARTS} parts of {} MiB", PART >> 20),
                ));
            }
            let part = format!("{what}: part {n}");
            let num = n.to_string();
            let hash = hex(&Sha256::digest(&buf));
            let req = || {
                self.request(
                    "PUT",
                    path,
                    &[("partNumber", &num), ("uploadId", id)],
                    &hash,
                    &[],
                )
            };
            let resp = success(&part, self.send_again(&part, req, &buf[..])?)?;
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .filter(|e| !e.is_empty())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{part}: no ETag"))
                })?;
            etags.push(etag.to_string());
            total += buf.len() as u64;
            if buf.len() < PART {
                break; // a short part: the body has ended
            }
            read_part(data, &mut buf)?;
        }
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (i, e) in etags.iter().enumerate() {
            let _ = write!(
                xml,
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                i + 1,
                xml_escape(e)
            );
        }
        xml.push_str("</CompleteMultipartUpload>");
        let done = format!("{what}: complete the multipart upload");
        let hash = hex(&Sha256::digest(xml.as_bytes()));
        // Sent once: a completion that was carried out answers a second
        // one with "no such upload".
        let req = self.request("POST", path, &[("uploadId", id)], &hash, &[]);
        let body = success(&done, self.send(&done, req, xml.as_bytes())?)?
            .body_mut()
            .read_to_string()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{done}: {e}")))?;
        // S3 may answer 200 and still fail the completion, in the body.
        if body.contains("<Error>") {
            let code = between(&body, "<Code>", "</Code>").unwrap_or_default();
            return Err(io::Error::other(format!("{done}: {code}")));
        }
        Ok(total)
    }
}

impl ObjectStore for S3Store {
    fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        let mut first = Vec::new();
        read_part(data, &mut first)?;
        if first.len() < PART {
            return self.put_whole(key, &first);
        }
        self.put_parts(key, first, data)
    }

    /// `None` for a key that is not there.  A 404 that says the bucket is
    /// not there (`NoSuchBucket`: missing, misnamed, another region's) is
    /// an error: it used to read as "the object is absent", and an absent
    /// object is a fact the Warden acts on (a Candidate's object gone, a
    /// pack never shipped) (audit 2026-11-09).
    fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        let what = format!("get {key}");
        let path = self.path(key);
        // The first piece (finding 7: an object is read in pieces).
        let range = [("range", format!("bytes=0-{}", self.piece - 1))];
        let req = || self.request("GET", &path, &[], EMPTY_SHA256, &range);
        let mut resp = self.send_again(&what, req, ())?;
        match resp.status() {
            http::StatusCode::NOT_FOUND => {
                let body = resp.body_mut().read_to_string().unwrap_or_default();
                if between(&body, "<Code>", "</Code>") == Some("NoSuchBucket") {
                    return Err(no_bucket(&what, &self.conn.config.bucket));
                }
                return Ok(None);
            }
            // An empty object has no byte 0: asked for again whole (the
            // refusal read first, so its connection is free again).
            http::StatusCode::RANGE_NOT_SATISFIABLE => {
                let _ = resp.body_mut().read_to_string();
                let req = || self.request("GET", &path, &[], EMPTY_SHA256, &[]);
                let resp = success(&what, self.send_again(&what, req, ())?)?;
                return Ok(Some(Box::new(resp.into_body().into_reader())));
            }
            http::StatusCode::PARTIAL_CONTENT => {}
            // A whole object to a ranged request (a store that ignores
            // Range), or an error.
            _ => {
                let resp = success(&what, resp)?;
                return Ok(Some(Box::new(resp.into_body().into_reader())));
            }
        }
        let Some((0, end, total)) = content_range(&resp) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{what}: the store answered bytes 0-{} with Content-Range {:?}",
                    self.piece - 1,
                    header(&resp, "content-range")
                ),
            ));
        };
        let etag = header(&resp, "etag");
        let first = resp.into_body().into_reader();
        Ok(Some(Box::new(Pieces::new(
            self,
            what,
            path,
            etag,
            total,
            end + 1,
            Box::new(first),
        ))))
    }

    fn exists(&self, key: &str) -> io::Result<bool> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        let what = format!("head {key}");
        let req = || self.request("HEAD", &self.path(key), &[], EMPTY_SHA256, &[]);
        let resp = self.send_again(&what, req, ())?;
        if resp.status() == http::StatusCode::NOT_FOUND {
            // A HEAD's answer has no body to say whose 404 it is: the
            // bucket is asked for once, and from then on a 404 is the key's.
            self.bucket_is_there(&what)?;
            return Ok(false);
        }
        success(&what, resp)?;
        self.bucket_seen
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(true)
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        Ok(self
            .list_pages(prefix)?
            .into_iter()
            .map(|(k, _)| k)
            .collect())
    }

    /// Each entry's `LastModified` (a PUT again makes it new).  An entry
    /// without one, or one that does not parse, fails the listing: an age
    /// is never guessed.
    fn list_times(&self, prefix: &str) -> io::Result<Vec<(String, SystemTime)>> {
        self.list_pages(prefix)?
            .into_iter()
            .map(|(k, t)| {
                let at = t.as_deref().and_then(parse_last_modified).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("list {prefix}: {k} has no LastModified the Warden reads ({t:?})"),
                    )
                })?;
                Ok((k, at))
            })
            .collect()
    }

    /// HEAD, then DELETE.  S3 answers a DELETE of a missing key with 204
    /// like any other, so the HEAD is what tells "removed" from "nothing
    /// to remove".  The two requests are not atomic, but nothing else
    /// writes a key while its deleter holds the coordinator's claim
    /// (P4 spec §2.4).
    ///
    /// On a bucket with versioning enabled, DELETE adds a delete marker and
    /// the bytes stay as a noncurrent version: that is the hosting
    /// platform's retention, not Taso's (P4 spec §0.4).
    fn delete(&self, key: &str) -> io::Result<bool> {
        if !self.exists(key)? {
            return Ok(false);
        }
        let what = format!("delete {key}");
        // Sent once: a delete that was carried out answers a second one
        // 404, which would read as "it was not there".
        let req = self.request("DELETE", &self.path(key), &[], EMPTY_SHA256, &[]);
        let resp = self.send(&what, req, ())?;
        if resp.status() == http::StatusCode::NOT_FOUND {
            return Ok(false); // gone between the HEAD and the DELETE
        }
        success(&what, resp)?;
        Ok(true)
    }
}

// ── ListObjectsV2 ───────────────────────────────────────────────────

struct Page {
    /// Each key, with its `LastModified` as given.
    keys: Vec<(String, Option<String>)>,
    next: Option<String>,
}

/// A header of `resp` as text, if it has it.
fn header(resp: &http::Response<ureq::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// `(first, last, total)` of a 206's `Content-Range: bytes first-last/total`.
fn content_range(resp: &http::Response<ureq::Body>) -> Option<(u64, u64, u64)> {
    let v = header(resp, "content-range")?;
    let (range, total) = v.strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let (first, last, total) = (first.parse().ok()?, last.parse().ok()?, total.parse().ok()?);
    (first <= last && last < total).then_some((first, last, total))
}

/// A size as a person reads it: bytes, MiB, or GiB to a tenth.
fn size(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GiB", b as f64 / f64::from(1u32 << 30))
    } else if b >= 1 << 20 {
        format!("{} MiB", b >> 20)
    } else {
        format!("{b} bytes")
    }
}

/// Why a piece's request failed.
enum Fail {
    /// Worth asking again (no answer, a broken or slow answer, a 5xx).
    Again(String),
    /// Not: the object changed or is gone, or the store refuses.
    Final(String),
}

/// An object read in pieces, each its own ranged GET (see the module
/// docs, "Downloads").  Made by [`S3Store::get`] with the first piece's
/// answer.
struct Pieces {
    conn: Conn,
    /// `get <key>`, the start of every line and error.
    what: String,
    path: String,
    /// The first answer's ETag: every later piece must be of that object.
    etag: Option<String>,
    total: u64,
    piece: u64,
    waits: [Duration; 3],
    /// The bytes handed to the reader so far.
    pos: u64,
    /// Where the current answer ends (exclusive).
    end: u64,
    /// The current answer's body; `None` between pieces.
    body: Option<Box<dyn Read + Send>>,
    /// The current piece's failed tries.
    failures: u32,
    /// The read failed for good: its error, again.
    dead: Option<String>,
    /// Larger than one piece: progress is logged.
    loud: bool,
    started: std::time::Instant,
    said: std::time::Instant,
    ended: bool,
}

impl Pieces {
    fn new(
        store: &S3Store,
        what: String,
        path: String,
        etag: Option<String>,
        total: u64,
        end: u64,
        first: Box<dyn Read + Send>,
    ) -> Self {
        let now = std::time::Instant::now();
        let p = Self {
            conn: store.conn.clone(),
            what,
            path,
            etag,
            total,
            piece: store.piece,
            waits: store.waits,
            pos: 0,
            end,
            body: Some(first),
            failures: 0,
            dead: None,
            loud: total > store.piece,
            started: now,
            said: now,
            ended: false,
        };
        if p.loud {
            p.say(format_args!(
                "{} in {} pieces",
                size(total),
                total.div_ceil(store.piece)
            ));
        }
        p
    }

    fn say(&self, line: std::fmt::Arguments<'_>) {
        eprintln!("taso: {}: {line}", self.what);
    }

    /// The piece the reader is in, from 1.
    fn number(&self) -> u64 {
        self.pos / self.piece + 1
    }

    /// Ask for the rest of the piece the reader is in, from `pos`, as part
    /// of the first answer's object.
    fn ask(&self) -> Result<(u64, Box<dyn Read + Send>), Fail> {
        let end = ((self.pos / self.piece + 1) * self.piece).min(self.total);
        let mut extra = vec![("range", format!("bytes={}-{}", self.pos, end - 1))];
        if let Some(e) = &self.etag {
            extra.push(("if-match", e.clone()));
        }
        let req = || {
            self.conn
                .request("GET", &self.path, &[], EMPTY_SHA256, &extra)
        };
        let mut resp = self
            .conn
            .send_again("no answer", req, ())
            .map_err(|e| Fail::Again(e.to_string()))?;
        let code = resp.status().as_u16();
        if code != 206 {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            let text = between(&body, "<Code>", "</Code>").unwrap_or_default();
            return Err(match code {
                412 => Fail::Final(format!(
                    "the object changed while it was read (it is no longer ETag {})",
                    self.etag.as_deref().unwrap_or("?")
                )),
                404 => Fail::Final("the object was deleted while it was read".into()),
                200 => Fail::Final(
                    "the store answered a later piece with the whole object (it ignores Range)"
                        .into(),
                ),
                c if c >= 500 || c == 408 || c == 429 => Fail::Again(format!("HTTP {c} {text}")),
                c => Fail::Final(format!("HTTP {c} {text}")),
            });
        }
        if let (Some(was), Some(now)) = (&self.etag, header(&resp, "etag")) {
            if *was != now {
                return Err(Fail::Final(format!(
                    "the object changed while it was read (ETag {was} became {now})"
                )));
            }
        }
        match content_range(&resp) {
            Some((first, last, total))
                if first == self.pos && last == end - 1 && total == self.total => {}
            _ => {
                return Err(Fail::Final(format!(
                    "the store answered bytes {}-{} of {} with Content-Range {:?}",
                    self.pos,
                    end - 1,
                    self.total,
                    header(&resp, "content-range")
                )))
            }
        }
        Ok((end, Box::new(resp.into_body().into_reader())))
    }

    /// The reader's error for good: a `FAILED` line, and the same text.
    fn failed(&mut self, why: &str) -> io::Error {
        let line = format!(
            "FAILED at {} of {} ({} %): {why}",
            size(self.pos),
            size(self.total),
            self.pos * 100 / self.total.max(1)
        );
        self.say(format_args!("{line}"));
        let e = format!("{}: {line}", self.what);
        self.dead = Some(e.clone());
        io::Error::other(e)
    }

    /// The current piece failed with `why`: wait and go on from `pos`, or,
    /// past the last try, fail for good.
    fn again(&mut self, why: String) -> io::Result<()> {
        self.body = None;
        self.failures += 1;
        let tries = self.waits.len() as u32 + 1;
        if self.failures >= tries {
            let n = self.number();
            return Err(self.failed(&format!("piece {n} failed {tries} times, last: {why}")));
        }
        self.say(format_args!(
            "piece {} failed ({why}): again from {}, try {} of {tries}",
            self.number(),
            size(self.pos),
            self.failures + 1
        ));
        std::thread::sleep(self.waits[self.failures as usize - 1]);
        Ok(())
    }

    fn progress(&mut self) {
        if !self.loud || self.said.elapsed() < PROGRESS_EVERY {
            return;
        }
        self.said = std::time::Instant::now();
        let rate = self.pos as f64 / self.started.elapsed().as_secs_f64();
        self.say(format_args!(
            "{} of {} ({} %), {:.0} MiB/s, about {:.0} s left",
            size(self.pos),
            size(self.total),
            self.pos * 100 / self.total,
            rate / f64::from(1u32 << 20),
            (self.total - self.pos) as f64 / rate
        ));
    }
}

impl Read for Pieces {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.dead {
            return Err(io::Error::other(e.clone()));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.body.is_none() {
                if self.pos >= self.total {
                    if self.loud && !self.ended {
                        self.ended = true;
                        let secs = self.started.elapsed().as_secs_f64();
                        self.say(format_args!(
                            "{} in {secs:.1} s, {:.0} MiB/s",
                            size(self.total),
                            self.total as f64 / f64::from(1u32 << 20) / secs
                        ));
                    }
                    return Ok(0);
                }
                match self.ask() {
                    Ok((end, body)) => {
                        self.end = end;
                        self.body = Some(body);
                    }
                    Err(Fail::Final(why)) => return Err(self.failed(&why)),
                    Err(Fail::Again(why)) => {
                        self.again(why)?;
                        continue;
                    }
                }
            }
            let want = buf.len().min((self.end - self.pos) as usize);
            let body = self.body.as_mut().expect("a piece is open");
            match body.read(&mut buf[..want]) {
                Ok(0) => {
                    let why = format!(
                        "its answer ended at {}, short of {}",
                        size(self.pos),
                        size(self.end)
                    );
                    self.again(why)?;
                }
                Ok(n) => {
                    self.pos += n as u64;
                    if self.pos == self.end {
                        // The piece is whole: the next one has its own tries.
                        self.body = None;
                        self.failures = 0;
                    }
                    self.progress();
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => self.again(e.to_string())?,
            }
        }
    }
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

/// Text for an XML element (an ETag in a multipart completion).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
        let modified = between(item, "<LastModified>", "</LastModified>").map(str::to_string);
        keys.push((xml_unescape(key), modified));
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

/// The most pages one listing follows before it is an error.  A Chronicle's
/// pack directory, the prefix the Warden lists, holds one pack per Seal;
/// at S3's 1000 keys a page this is ten million Seals of one Vessel --
/// unreachable by design, so a constant rather than a config key.  Hitting
/// it says so; it never truncates.
const MAX_LIST_PAGES: u32 = 10_000;

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

/// A `LastModified` of `ListObjectsV2`: `YYYY-MM-DDTHH:MM:SS[.fraction]Z`
/// in UTC (S3 and Garage), to the second.  Anything else is `None`.
fn parse_last_modified(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let d = b.get(r)?;
        if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(d).ok()?.parse().ok()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last()? != b'Z'
    {
        return None;
    }
    match &b[19..b.len() - 1] {
        [] => {}
        [b'.', frac @ ..] if !frac.is_empty() && frac.iter().all(u8::is_ascii_digit) => {}
        _ => return None,
    }
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days since 1970-01-01 from a civil date (Howard Hinnant's algorithm),
    // the inverse of amz_date's.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss;
    UNIX_EPOCH.checked_add(std::time::Duration::from_secs(u64::try_from(secs).ok()?))
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
            plaintext: true,
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
             <Contents><Key>v/a/pack/1</Key><LastModified>2026-11-06T10:00:00.000Z</LastModified><Size>3</Size></Contents>\
             <Contents><Key>v/a/pack/2</Key></Contents>\
             <NextContinuationToken>tok&amp;en</NextContinuationToken></ListBucketResult>",
        )
        .unwrap();
        assert_eq!(
            page.keys,
            vec![
                (
                    "v/a/pack/1".to_string(),
                    Some("2026-11-06T10:00:00.000Z".to_string())
                ),
                ("v/a/pack/2".to_string(), None)
            ]
        );
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

    /// The reclaimer's ages (review fix 2a): `LastModified` read to the
    /// second, as amz_date writes the same instants; anything else is no
    /// age at all, never a guessed one.
    #[test]
    fn last_modified_is_read_to_the_second_or_not_at_all() {
        for secs in [0u64, 951_782_400, 1_762_423_200, 4_102_444_799] {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            let a = amz_date(t); // YYYYMMDDTHHMMSSZ
            let iso = format!(
                "{}-{}-{}T{}:{}:{}.123Z",
                &a[0..4],
                &a[4..6],
                &a[6..8],
                &a[9..11],
                &a[11..13],
                &a[13..15]
            );
            assert_eq!(parse_last_modified(&iso), Some(t), "{iso}");
            assert_eq!(parse_last_modified(&iso.replace(".123", "")), Some(t));
        }
        assert_eq!(
            parse_last_modified("2026-11-06T10:00:00Z"),
            Some(UNIX_EPOCH + Duration::from_secs(1_793_959_200))
        );
        for bad in [
            "",
            "2026-11-06",
            "2026-11-06T10:00:00",
            "2026-11-06 10:00:00Z",
            "2026-13-06T10:00:00Z",
            "2026-11-06T24:00:00Z",
            "2026-11-06T10:00:00.Z",
            "2026-11-06T10:00:00+00:00",
            "Thu, 06 Nov 2026 10:00:00 GMT",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_last_modified(bad), None, "{bad:?}");
        }
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
        let https = S3Config {
            endpoint: "https://garage.example:3900".into(),
            plaintext: false,
            ..ok.clone()
        };
        assert!(S3Store::new(https.clone(), Duration::from_secs(1)).is_ok());
        // Review fix M4: http:// only with the operator's yes, and that
        // yes with https:// is a contradiction.
        let e = S3Store::new(
            S3Config {
                plaintext: false,
                ..ok.clone()
            },
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(e.to_string().contains("plain http"), "{e}");
        assert!(S3Store::new(
            S3Config {
                plaintext: true,
                ..https
            },
            Duration::from_secs(1)
        )
        .is_err());
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
        # The bucket is there; every key in it is not.
        ok = self.path.rstrip("/") == "/taso"
        self.send_response(200 if ok else 404); self.send_header("Content-Length", "0"); self.end_headers()
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
                    plaintext: false,
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

    /// A stand-in whose every answer is 404; with `bucket` the bucket
    /// itself is there (a HEAD of it is 200) and a GET's 404 says
    /// NoSuchKey, else NoSuchBucket.
    fn four_oh_four(bucket: bool) -> TestServer {
        let code = if bucket { "NoSuchKey" } else { "NoSuchBucket" };
        TestServer::start(
            false,
            &format!(
                r#"
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"<Error><Code>{code}</Code><Message>m</Message></Error>"
        self.send_response(404)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_HEAD(self):
        ok = {bucket} and self.path.rstrip("/") == "/tsao"
        self.send_response(200 if ok else 404); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
"#,
                bucket = if bucket { "True" } else { "False" },
            ),
        )
    }

    fn store_at(port: u16) -> S3Store {
        S3Store::new(
            S3Config {
                endpoint: format!("http://127.0.0.1:{port}"),
                region: "garage".into(),
                bucket: "tsao".into(),
                plaintext: true,
                ..aws_example()
            },
            Duration::from_secs(5),
        )
        .unwrap()
    }

    /// Audit 2026-11-09, a 404 because the bucket is missing or misnamed
    /// read as "the object is absent", and the Warden acts on an absent
    /// object (a Candidate's object gone, a pack never shipped).  GET and
    /// HEAD both answer an error then; with the bucket there, a missing
    /// key is still `None` and `false`.
    #[test]
    fn a_missing_bucket_is_not_an_absent_object() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = four_oh_four(false);
        let store = store_at(srv.port);
        let got = store.get("d/a").map(|o| o.is_some());
        assert!(
            got.as_ref()
                .is_err_and(|e| e.to_string().contains("NoSuchBucket")),
            "get answered {got:?} for a 404 NoSuchBucket"
        );
        let head = store.exists("d/a");
        assert!(
            head.as_ref()
                .is_err_and(|e| e.to_string().contains("does not exist")),
            "exists answered {head:?} with no bucket"
        );
        let srv = four_oh_four(true);
        let store = store_at(srv.port);
        assert!(store.get("d/a").unwrap().is_none());
        assert!(!store.exists("d/a").unwrap());
        assert!(
            !store.exists("d/b").unwrap(),
            "the bucket is asked for once"
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
        # A HEAD of the bucket itself: it is there.
        self.reply(200 if k in objs or k == "" else 404)
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
            # A broken endpoint: under stuck/ the token never advances.
            if prefix.startswith("stuck/"):
                xml = "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>0</NextContinuationToken>"
            return self.reply(200, (xml + "</ListBucketResult>").encode())
        if k not in objs: return self.error(404, "NoSuchKey")
        self.reply(200, objs[k], "application/octet-stream")
    def do_DELETE(self):
        b, k, _ = self.key()
        if not self.signed(): return self.error(403, "AccessDenied")
        if k.startswith("deny/"): return self.error(403, "AccessDenied")
        objs.pop(k, None)
        self.reply(204)
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
        assert!(store.delete("d/a").unwrap(), "it was there");
        assert!(!store.exists("d/a").unwrap());
        assert!(!store.delete("d/a").unwrap(), "a retry is a no-op");
        assert_eq!(
            store.list("d").unwrap(),
            vec!["d/c".to_string(), "d/sub/b".into()],
            "the others stay"
        );
        assert!(store.delete("../x").is_err(), "invalid keys are refused");
        let e = store.list("stuck").unwrap_err();
        assert!(
            e.to_string().contains("repeated its continuation token"),
            "a listing that does not advance is an error, not a loop: {e}"
        );
        drop(srv);
        assert_eq!(
            store.exists("d/a").unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted,
            "no server: a transport error"
        );
    }
    // ── Downloads in pieces (finding 7) ───────────────────────────

    /// A stand-in store for downloads (finding 7, D&D 7-a…7-c): one
    /// 10,000-byte object under every key, served by range with an ETag,
    /// each key misbehaving its own way from its second request on (a
    /// later piece).  `asked/<key>` answers how often `<key>` was asked.
    fn pieces_server() -> TestServer {
        TestServer::start(
            false,
            r#"
import time
N = 10000
data = bytes((i * 7 + i // 251) % 256 for i in range(N))
asked = {}
etags = {}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def head(self, code, n, headers=()):
        self.send_response(code)
        for k, v in headers: self.send_header(k, v)
        self.send_header("Content-Length", str(n))
        self.end_headers()
    def reply(self, code, body, headers=()):
        self.head(code, len(body), headers); self.wfile.write(body)
    def do_GET(self):
        k = self.path.split("/", 2)[2]
        if k.startswith("asked/"):
            return self.reply(200, str(asked.get(k[6:], 0)).encode())
        n = asked[k] = asked.get(k, 0) + 1
        m = k.rsplit("/", 1)[-1]
        body = b"" if m == "empty" else data
        tag = etags.setdefault(k, '"e1"')
        r = self.headers.get("range")
        if m == "whole" or r is None:
            return self.reply(200, body, [("ETag", tag)])
        a, b = (int(x) for x in r[6:].split("-"))
        if a >= len(body):
            return self.reply(416, b"<Error><Code>InvalidRange</Code></Error>")
        b = min(b, len(body) - 1)
        if n > 1:
            if m == "gone": return self.reply(404, b"<Error><Code>NoSuchKey</Code></Error>")
            if m in ("change", "match"): tag = etags[k] = '"e2"'
            if m == "match" and self.headers.get("if-match") != tag:
                return self.reply(412, b"<Error><Code>PreconditionFailed</Code></Error>")
            if m == "flaky" and n == 2:
                return self.reply(503, b"<Error><Code>SlowDown</Code></Error>")
        part = body[a:b + 1]
        self.head(206, len(part), [("ETag", tag), ("Content-Range", "bytes %d-%d/%d" % (a, b, len(body)))])
        if m == "drop" and n == 2:
            self.wfile.write(part[:len(part) // 2]); self.wfile.flush()
            self.close_connection = True
            return
        if m == "stall" and a >= 4096: time.sleep(0.6)
        if m == "slow":
            for i in range(0, len(part), 4096):
                time.sleep(0.3); self.wfile.write(part[i:i + 4096]); self.wfile.flush()
            return
        self.wfile.write(part)
    def log_message(self, *a): pass
"#,
        )
    }

    /// What the stand-in serves under every key.
    fn pieces_data() -> Vec<u8> {
        (0..10_000u32)
            .map(|i| ((i * 7 + i / 251) % 256) as u8)
            .collect()
    }

    fn read_whole(store: &S3Store, key: &str) -> io::Result<Vec<u8>> {
        let mut got = Vec::new();
        store.get(key)?.expect("there").read_to_end(&mut got)?;
        Ok(got)
    }

    fn asked(store: &S3Store, key: &str) -> u32 {
        let got = read_whole(store, &format!("asked/{key}")).unwrap();
        String::from_utf8(got).unwrap().parse().unwrap()
    }

    /// An object over three pieces of 4,096 bytes is read whole, one
    /// request a piece; a piece whose answer breaks off, or that gets a
    /// 503, goes on from the byte it reached.  A store that ignores Range,
    /// and an empty object (no byte 0), still read.
    #[test]
    fn an_object_is_read_in_pieces_and_a_broken_piece_goes_on() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = pieces_server();
        let store =
            store_at(srv.port).tuned(4096, Duration::from_secs(5), Duration::from_millis(10));
        let data = pieces_data();
        assert_eq!(read_whole(&store, "d/ok").unwrap(), data);
        assert_eq!(asked(&store, "d/ok"), 3, "one request a piece");
        assert_eq!(read_whole(&store, "d/drop").unwrap(), data);
        assert_eq!(asked(&store, "d/drop"), 4, "the broken piece asked again");
        assert_eq!(read_whole(&store, "d/flaky").unwrap(), data);
        assert_eq!(asked(&store, "d/flaky"), 4, "the 503 asked again");
        assert_eq!(read_whole(&store, "d/whole").unwrap(), data);
        assert_eq!(asked(&store, "d/whole"), 1);
        assert_eq!(read_whole(&store, "d/empty").unwrap(), b"");
    }

    /// D&D 7-c: a piece that fails every try ends the read with a FAILED
    /// error that says where and why, after four tries.
    #[test]
    fn a_piece_that_keeps_failing_fails_the_read_clearly() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = pieces_server();
        let store =
            store_at(srv.port).tuned(4096, Duration::from_millis(200), Duration::from_millis(10));
        let e = read_whole(&store, "d/stall").unwrap_err().to_string();
        assert!(
            e.starts_with("get d/stall: FAILED at 4096 bytes of 10000 bytes (40 %): piece 2 failed 4 times, last: "),
            "{e}"
        );
        assert_eq!(
            asked(&store, "d/stall"),
            5,
            "the first piece, and four tries of the second"
        );
    }

    /// D&D 7-b: an object that changes while it is read ends the read at
    /// once, not retried: answered 412 by a store that honours If-Match,
    /// or seen by its ETag where the store ignores If-Match.  So does an
    /// object deleted meanwhile.
    #[test]
    fn an_object_changed_or_deleted_while_it_is_read_ends_the_read() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = pieces_server();
        let store =
            store_at(srv.port).tuned(4096, Duration::from_secs(5), Duration::from_millis(10));
        for (key, why) in [
            (
                "d/change",
                r#"the object changed while it was read (ETag "e1" became "e2")"#,
            ),
            (
                "d/match",
                r#"the object changed while it was read (it is no longer ETag "e1")"#,
            ),
            ("d/gone", "the object was deleted while it was read"),
        ] {
            let e = read_whole(&store, key).unwrap_err().to_string();
            assert_eq!(
                e,
                format!("get {key}: FAILED at 4096 bytes of 10000 bytes (40 %): {why}")
            );
            assert_eq!(asked(&store, key), 2, "{key}: not asked again");
        }
    }

    /// The maturity review's finding 7: one limit on the whole call cut a
    /// download that took longer.  The object arrives at 4 KiB per 300 ms,
    /// 900 ms in all, with every limit at 500 ms: read whole, a piece of
    /// 4 KiB at a time, none asked again.
    #[test]
    fn a_download_longer_than_any_limit_is_not_cut() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = pieces_server();
        let store = S3Store::new(
            S3Config {
                endpoint: format!("http://127.0.0.1:{}", srv.port),
                region: "garage".into(),
                bucket: "tsao".into(),
                plaintext: true,
                ..aws_example()
            },
            Duration::from_millis(500),
        )
        .unwrap()
        .tuned(4096, Duration::from_millis(500), Duration::from_millis(10));
        let t = std::time::Instant::now();
        assert_eq!(read_whole(&store, "d/slow").unwrap(), pieces_data());
        assert!(
            t.elapsed() > Duration::from_millis(800),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(asked(&store, "d/slow"), 3, "no piece asked again");
    }

    /// A reader that hands out at most 7,777 bytes a call, as a pipe or
    /// a stream producer may: a part must still be read whole.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len()).min(7_777);
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// Audit 2026-11-16, S3: a body over one part goes as a multipart
    /// upload, no request larger than a part (the stand-in refuses one);
    /// it reads back byte for byte; one that fits a part is still one
    /// PUT; a failed part and a completion refused in a 200's body are
    /// errors, and the upload is aborted.
    #[test]
    fn a_large_object_goes_in_parts_and_a_failed_upload_is_aborted() {
        if !have_tools() {
            eprintln!("skipped: needs openssl and python3");
            return;
        }
        let srv = TestServer::start(
            false,
            &r#"
import hashlib, urllib.parse
PART = @PART@
objs, uploads = {}, {}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def reply(self, code, body=b"", ctype="application/xml", etag=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if etag: self.send_header("ETag", etag)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def error(self, code, name):
        self.reply(code, ("<Error><Code>%s</Code><Message>m</Message></Error>" % name).encode())
    def parse(self):
        u = urllib.parse.urlparse(self.path)
        k = urllib.parse.unquote(u.path).split("/", 2)[2]
        q = {a: b[0] for a, b in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        if n > PART: return k, q, None
        if self.headers.get("x-amz-content-sha256") not in (hashlib.sha256(body).hexdigest(), None):
            return k, q, None
        return k, q, body
    def do_PUT(self):
        k, q, body = self.parse()
        if body is None: return self.error(400, "EntityTooLarge or BadDigest")
        if "uploadId" not in q:
            objs[k] = body
            return self.reply(200)
        n = int(q["partNumber"])
        if k.startswith("fail/") and n == 2: return self.error(500, "InternalError")
        etag = '"%s"' % hashlib.md5(body).hexdigest()
        uploads[q["uploadId"]][1][n] = (etag, body)
        self.reply(200, etag=etag)
    def do_POST(self):
        k, q, body = self.parse()
        if "uploads" in q:
            uid = "u&%d" % len(uploads)
            uploads[uid] = (k, {})
            return self.reply(200, ("<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>" % uid.replace("&", "&amp;")).encode())
        key, parts = uploads[q["uploadId"]]
        listed = body.decode()
        want = "".join("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (n, parts[n][0]) for n in sorted(parts))
        if listed != "<CompleteMultipartUpload>%s</CompleteMultipartUpload>" % want:
            return self.error(400, "InvalidPart")
        if k.startswith("late/"):
            return self.reply(200, b"<Error><Code>InternalError</Code></Error>")
        objs[k] = b"".join(parts[n][1] for n in sorted(parts))
        objs["parts/" + k] = str(len(parts)).encode()
        del uploads[q["uploadId"]]
        self.reply(200, b"<CompleteMultipartUploadResult/>")
    def do_DELETE(self):
        k, q, _ = self.parse()
        if "uploadId" in q:
            uploads.pop(q["uploadId"], None)
            objs["aborted/" + k] = b""
        else:
            objs.pop(k, None)
        self.reply(204)
    def do_HEAD(self):
        k = urllib.parse.unquote(urllib.parse.urlparse(self.path).path).split("/", 2)
        self.reply(200 if len(k) < 3 or k[2] in objs else 404)
    def do_GET(self):
        k, q, _ = self.parse()
        if k not in objs: return self.error(404, "NoSuchKey")
        self.reply(200, objs[k], "application/octet-stream")
    def log_message(self, *a): pass
"#
            .replace("@PART@", &PART.to_string()),
        );
        let store = store_at(srv.port);
        let read = |k: &str| {
            let mut got = Vec::new();
            store
                .get(k)
                .unwrap()
                .unwrap()
                .read_to_end(&mut got)
                .unwrap();
            got
        };
        let big: Vec<u8> = (0..2 * PART + 12_345)
            .map(|i| (i * 31 + i / 997) as u8)
            .collect();
        let n = store.put("d/big", &mut Trickle(&big)).unwrap();
        assert_eq!(n, big.len() as u64);
        assert!(read("d/big") == big, "read back byte for byte");
        assert_eq!(read("parts/d/big"), b"3");
        // Exactly one part: a multipart upload of one part.
        store.put("d/one", &mut Trickle(&big[..PART])).unwrap();
        assert!(read("d/one") == big[..PART]);
        assert_eq!(read("parts/d/one"), b"1");
        // A byte less: one PUT.
        store
            .put("d/small", &mut Trickle(&big[..PART - 1]))
            .unwrap();
        assert!(read("d/small") == big[..PART - 1]);
        assert!(!store.exists("parts/d/small").unwrap());
        // A part refused: an error, and the upload aborted.
        let e = store.put("fail/x", &mut Trickle(&big)).unwrap_err();
        assert!(
            e.to_string().contains("part 2: HTTP 500 InternalError"),
            "{e}"
        );
        assert!(!store.exists("fail/x").unwrap());
        assert!(
            store.exists("aborted/fail/x").unwrap(),
            "the upload was aborted"
        );
        // The completion refused in a 200's body: the same.
        let e = store.put("late/x", &mut Trickle(&big)).unwrap_err();
        assert!(e.to_string().contains("InternalError"), "{e}");
        assert!(!store.exists("late/x").unwrap());
        assert!(
            store.exists("aborted/late/x").unwrap(),
            "the upload was aborted"
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
                plaintext: env("TASO_S3_ENDPOINT").starts_with("http://"),
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
        // Over one part: a multipart upload (audit 2026-11-16, S3).
        let huge: Vec<u8> = (0..2 * PART + 5).map(|i| (i / 3) as u8).collect();
        assert_eq!(
            store.put(&k("huge"), &mut &huge[..]).unwrap(),
            huge.len() as u64
        );
        let mut got = Vec::new();
        store
            .get(&k("huge"))
            .unwrap()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert!(got == huge, "the multipart object reads back whole");
        assert!(store.delete(&k("huge")).unwrap());
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
        // Every entry has an age the Warden reads, from Garage's clock: a
        // minute's skew either way is allowed (review fix 2a).
        let now = SystemTime::now();
        for (key, at) in store.list_times(&dir).unwrap() {
            let skew = at
                .duration_since(now)
                .or_else(|_| now.duration_since(at))
                .unwrap();
            assert!(
                skew < Duration::from_secs(60),
                "{key}: {at:?} against {now:?}"
            );
        }
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
                ..store.conn.config.clone()
            },
            Duration::from_secs(10),
        )
        .unwrap();
        let e = wrong.put(&k("c"), &mut &b"x"[..]).unwrap_err();
        println!("a wrong secret: {e}");
        assert!(!store.exists(&k("c")).unwrap());
        assert!(
            wrong.delete(&k("a")).is_err(),
            "a wrong secret deletes nothing"
        );
        assert!(store.exists(&k("a")).unwrap());
        assert!(store.delete(&k("a")).unwrap());
        assert!(!store.exists(&k("a")).unwrap());
        assert!(!store.delete(&k("a")).unwrap(), "a retry is a no-op");
        // Leave the bucket as found.
        for key in store.list(&dir).unwrap() {
            assert!(store.delete(&key).unwrap());
        }
        assert_eq!(store.list(&dir).unwrap(), Vec::<String>::new());
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
