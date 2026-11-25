//! A request to the store that a signal interrupts is sent again.
//!
//! taso-test, 2026-11-25: one part's upload failed with "Interrupted
//! system call" in the Warden's unit tests, and the whole put with it.
//! A signal that interrupts a socket call is not a broken connection: a
//! stopped and continued process gets `EINTR` from a socket call with a
//! timeout whatever its handlers are.  `S3Store` sends a request that
//! may be sent again (a GET, a HEAD, a PUT of the same bytes) again.
//!
//! This is a program of its own because it installs a signal handler
//! and signals its own thread: in the unit tests' process that would
//! reach other tests, and the library denies `unsafe`.  It needs
//! `python3` for the stand-in store and is skipped without it.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use taso_warden::s3::{S3Config, S3Store};
use taso_warden::ship::ObjectStore;

/// One signal every this many microseconds, while [`ROUNDS`] objects of
/// [`BYTES`] are put and read back.
const SIGNAL_EVERY_US: u64 = 5_000;
const ROUNDS: usize = 40;
const BYTES: usize = 4 << 20;

const SERVER: &str = r#"
import http.server, sys
objs = {}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def do_PUT(self):
        objs[self.path] = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply(200)
    def do_GET(self):
        b = objs.get(self.path)
        if b is None: return self.reply(404)
        self.reply(200, b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
"#;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The stand-in store on a free port, answering; `None` without python3.
fn server() -> Option<(Server, u16)> {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new("python3")
        .args(["-c", SERVER, &port.to_string()])
        .stdin(Stdio::null())
        .spawn()
        .ok()?;
    let srv = Server(child);
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < until, "the stand-in store did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Some((srv, port))
}

static SIGNALS: AtomicU64 = AtomicU64::new(0);

/// Does nothing but count: installed without `SA_RESTART`, so a call it
/// interrupts answers `EINTR`, as after a stop and a continue.
extern "C" fn count(_: libc::c_int) {
    SIGNALS.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn a_request_interrupted_by_a_signal_is_sent_again() {
    let Some((_srv, port)) = server() else {
        eprintln!("skipped: needs python3");
        return;
    };
    let store = S3Store::new(
        S3Config {
            endpoint: format!("http://127.0.0.1:{port}"),
            region: "garage".into(),
            bucket: "taso".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ca_file: None,
            plaintext: true,
        },
        Duration::from_secs(20),
    )
    .unwrap();

    // SAFETY: the handler only adds to an atomic; the struct is zeroed
    // and then filled as sigaction(2) asks.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = count as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()), 0);
    }
    // SAFETY: names the calling thread.
    let me = unsafe { libc::pthread_self() };
    let stop = Arc::new(AtomicBool::new(false));
    let poker = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // SAFETY: `me` is the test's thread, which joins this one
                // before it ends.
                unsafe { libc::pthread_kill(me, libc::SIGUSR1) };
                std::thread::sleep(Duration::from_micros(SIGNAL_EVERY_US));
            }
        })
    };

    let body: Vec<u8> = (0..BYTES).map(|i| (i % 251) as u8).collect();
    let mut failed = Vec::new();
    for i in 0..ROUNDS {
        let key = format!("d/{i}");
        if let Err(e) = store.put(&key, &mut &body[..]) {
            failed.push(e.to_string());
            continue;
        }
        match store.get(&key) {
            Ok(Some(mut r)) => {
                let mut got = Vec::new();
                r.read_to_end(&mut got).unwrap();
                assert!(got == body, "{key} is read back whole");
            }
            Ok(None) => failed.push(format!("{key} is not there")),
            Err(e) => failed.push(e.to_string()),
        }
    }
    stop.store(true, Ordering::Relaxed);
    poker.join().unwrap();
    let signals = SIGNALS.load(Ordering::Relaxed);
    eprintln!("{signals} signals over {ROUNDS} puts and gets");
    assert!(signals > 100, "the test's signals arrived: {signals}");
    assert_eq!(failed, Vec::<String>::new());
}
