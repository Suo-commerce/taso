//! A minimal Kubernetes API client (K2; plan: claude/Taso_plan_k8s_docker_2026-10-17.md).
//!
//! The Warden needs three things from the API server: list the `Vessel`
//! resources for its node, read one, and write their status.  This client
//! does only that, synchronously, on the HTTP and TLS stack the crate
//! already uses for S3 (`ureq`, rustls) — no async runtime and no generated
//! API types.
//!
//! # Deliberately small
//!
//! - **Read and status only.**  `get` and `patch_status` (a JSON merge patch
//!   of the `status` subresource).  There is no create, update or delete:
//!   the Warden's credentials need no more, and a client that cannot do
//!   more cannot be made to.
//! - **Paths are built here, from validated names.**  Namespaces and object
//!   names must be valid Kubernetes names ([`valid_name`]); nothing from a
//!   resource is pasted into a URL unchecked.
//! - **HTTPS only**, trusting the cluster CA (in a pod, the service
//!   account's `ca.crt`) or, without one, the public roots.
//! - **The token is read on every request**: a pod's service-account token
//!   is projected and rotated by the kubelet; a cached one would expire.
//!
//! An API error arrives as [`KubeError::Status`] with the server's code,
//! `reason` and `message`; a transport failure as [`KubeError::Transport`]
//! (outcome unknown for a patch).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

/// Where a pod finds its service account.
pub const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// How to reach the API server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubeConfig {
    /// `https://host:port`, no trailing slash.
    pub api: String,
    /// A file holding the bearer token (re-read on every request).
    pub token_file: PathBuf,
    /// The CA to trust; `None` trusts the public roots.
    pub ca_file: Option<PathBuf>,
}

impl KubeConfig {
    /// The in-cluster configuration of a pod: `KUBERNETES_SERVICE_HOST`
    /// and `KUBERNETES_SERVICE_PORT`, the service account's token and CA.
    pub fn in_cluster() -> io::Result<Self> {
        let var = |k: &str| {
            std::env::var(k).map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("{k} is not set: not running in a pod?")))
        };
        Self::from_parts(&var("KUBERNETES_SERVICE_HOST")?, &var("KUBERNETES_SERVICE_PORT")?, Path::new(SERVICE_ACCOUNT_DIR))
    }

    /// The configuration for `host:port` with the service account files in
    /// `dir` (`token`, `ca.crt`).
    pub fn from_parts(host: &str, port: &str, dir: &Path) -> io::Result<Self> {
        let bad = |why: String| io::Error::new(io::ErrorKind::InvalidInput, why);
        if host.is_empty() || host.contains(['/', '?', '#', '@', ' ']) {
            return Err(bad(format!("bad API host {host:?}")));
        }
        port.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| bad(format!("bad API port {port:?}")))?;
        // An IPv6 address goes in brackets.
        let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
        Ok(Self { api: format!("https://{host}:{port}"), token_file: dir.join("token"), ca_file: Some(dir.join("ca.crt")) })
    }
}

/// Why a request failed.
#[derive(Debug)]
pub enum KubeError {
    /// The API server answered with an error status.
    Status {
        /// The HTTP status code.
        code: u16,
        /// The `Status` object's `reason` (e.g. `NotFound`, `Forbidden`), if any.
        reason: String,
        /// Its `message`, or the body.
        message: String,
    },
    /// No answer (connection, TLS, timeout): for a patch, the outcome is unknown.
    Transport(String),
    /// An answer that is not the JSON expected.
    Body(String),
    /// The token file could not be read, or is empty.
    Token(String),
    /// A namespace or name that is not a valid Kubernetes name.
    BadName(String),
}

impl KubeError {
    /// The object does not exist (404).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Status { code: 404, .. })
    }
}

impl fmt::Display for KubeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { code, reason, message } => write!(f, "API server: {code} {reason}: {message}"),
            Self::Transport(e) => write!(f, "API server unreachable: {e}"),
            Self::Body(e) => write!(f, "API server answer: {e}"),
            Self::Token(e) => write!(f, "service account token: {e}"),
            Self::BadName(n) => write!(f, "not a valid Kubernetes name: {n:?}"),
        }
    }
}

impl std::error::Error for KubeError {}

/// Whether `s` is a valid Kubernetes object or namespace name (a DNS
/// subdomain: lowercase letters, digits, `-` and `.`, starting and ending
/// with a letter or digit, at most 253 characters).  Anything that is not
/// can never be put into a request path.
pub fn valid_name(s: &str) -> bool {
    let ok_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.';
    let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    !s.is_empty() && s.len() <= 253 && s.chars().all(ok_char) && edge(s.chars().next()) && edge(s.chars().last())
}

/// A resource type served by the API: the path prefix of its collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    /// API group (`""` for the core group).
    pub group: &'static str,
    /// Version, e.g. `v1alpha1`.
    pub version: &'static str,
    /// Plural name, e.g. `vessels`.
    pub plural: &'static str,
}

impl Resource {
    fn prefix(&self) -> String {
        if self.group.is_empty() {
            format!("/api/{}", self.version)
        } else {
            format!("/apis/{}/{}", self.group, self.version)
        }
    }
}

/// The client (see the module docs).
pub struct Kube {
    agent: ureq::Agent,
    api: String,
    token_file: PathBuf,
}

impl fmt::Debug for Kube {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kube").field("api", &self.api).field("token_file", &self.token_file).finish()
    }
}

impl Kube {
    /// A client for `config`; every request times out after `timeout`.
    pub fn new(config: &KubeConfig, timeout: Duration) -> io::Result<Self> {
        let api = config.api.trim_end_matches('/');
        if !api.starts_with("https://") || api.len() <= "https://".len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the API server must be https://…, not {api:?}")));
        }
        let mut agent = ureq::AgentBuilder::new().timeout(timeout);
        if let Some(ca) = &config.ca_file {
            agent = agent.tls_config(std::sync::Arc::new(crate::s3::tls_trusting(ca)?));
        }
        Ok(Self { agent: agent.build(), api: api.to_string(), token_file: config.token_file.clone() })
    }

    fn token(&self) -> Result<String, KubeError> {
        let t = std::fs::read_to_string(&self.token_file).map_err(|e| KubeError::Token(format!("{}: {e}", self.token_file.display())))?;
        let t = t.trim();
        if t.is_empty() || t.contains(['\r', '\n']) {
            return Err(KubeError::Token(format!("{} holds no single token", self.token_file.display())));
        }
        Ok(t.to_string())
    }

    /// The path of a namespaced object, or of the whole collection (across
    /// namespaces when `namespace` is `None`).
    fn path(&self, r: Resource, namespace: Option<&str>, name: Option<&str>) -> Result<String, KubeError> {
        let mut p = r.prefix();
        if let Some(ns) = namespace {
            if !valid_name(ns) {
                return Err(KubeError::BadName(ns.into()));
            }
            p.push_str(&format!("/namespaces/{ns}"));
        }
        p.push('/');
        p.push_str(r.plural);
        if let Some(n) = name {
            if !valid_name(n) {
                return Err(KubeError::BadName(n.into()));
            }
            p.push_str(&format!("/{n}"));
        }
        Ok(p)
    }

    fn send(&self, req: ureq::Request, body: Option<&Value>) -> Result<Value, KubeError> {
        let req = req.set("Authorization", &format!("Bearer {}", self.token()?)).set("Accept", "application/json");
        let answer = match body {
            None => req.call(),
            Some(b) => req.set("Content-Type", "application/merge-patch+json").send_string(&b.to_string()),
        };
        match answer {
            Ok(resp) => {
                let text = resp.into_string().map_err(|e| KubeError::Body(e.to_string()))?;
                serde_json::from_str(&text).map_err(|e| KubeError::Body(format!("not JSON: {e}")))
            }
            Err(ureq::Error::Status(code, resp)) => Err(status_error(code, &resp.into_string().unwrap_or_default())),
            Err(ureq::Error::Transport(t)) => Err(KubeError::Transport(t.to_string())),
        }
    }

    /// List `r` in `namespace` (all namespaces if `None`), with a field
    /// selector if given (e.g. `spec.node=node-a`, for fields the CRD
    /// declares selectable).  Returns the `List` object.
    pub fn list(&self, r: Resource, namespace: Option<&str>, field_selector: Option<&str>) -> Result<Value, KubeError> {
        let url = format!("{}{}", self.api, self.path(r, namespace, None)?);
        let mut req = self.agent.get(&url);
        if let Some(fs) = field_selector {
            req = req.query("fieldSelector", fs);
        }
        self.send(req, None)
    }

    /// One object.
    pub fn get(&self, r: Resource, namespace: &str, name: &str) -> Result<Value, KubeError> {
        let url = format!("{}{}", self.api, self.path(r, Some(namespace), Some(name))?);
        self.send(self.agent.get(&url), None)
    }

    /// Merge `status` into the object's status (the `status` subresource,
    /// JSON merge patch).  Returns the object as the server now has it.
    pub fn patch_status(&self, r: Resource, namespace: &str, name: &str, status: &Value) -> Result<Value, KubeError> {
        self.patch_status_at(r, namespace, name, None, status)
    }

    /// [`Kube::patch_status`], applied only if the object is still at
    /// `resource_version` (else `409 Conflict`, nothing written).  This is
    /// the only precondition a status patch honours: a `metadata.uid` in
    /// the patch is ignored (measured on kube-apiserver 1.35), so "still the
    /// object I read" is checked by its resourceVersion.
    pub fn patch_status_at(
        &self,
        r: Resource,
        namespace: &str,
        name: &str,
        resource_version: Option<&str>,
        status: &Value,
    ) -> Result<Value, KubeError> {
        let url = format!("{}{}/status", self.api, self.path(r, Some(namespace), Some(name))?);
        let mut body = serde_json::json!({ "status": status });
        if let Some(rv) = resource_version {
            if rv.is_empty() {
                return Err(KubeError::BadName("an empty resourceVersion".into()));
            }
            body["metadata"] = serde_json::json!({ "resourceVersion": rv });
        }
        self.send(self.agent.request("PATCH", &url), Some(&body))
    }
}

/// An error answer: the `Status` object's reason and message if the body
/// is one, else the body itself.
fn status_error(code: u16, body: &str) -> KubeError {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    KubeError::Status {
        code,
        reason: s("reason").unwrap_or_default(),
        message: s("message").unwrap_or_else(|| body.chars().take(200).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VESSELS: Resource = Resource { group: "taso.suocommerce.com", version: "v1alpha1", plural: "vessels" };

    #[test]
    fn names_are_checked_before_they_reach_a_path() {
        for ok in ["default", "a", "vessel-1", "a.b-c.d", &"a".repeat(253)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "A", "a/b", "../x", "a?b", "a b", "-a", "a-", ".a", "a.", "ä", "a%2fb", &"a".repeat(254)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    fn client() -> (tempfile::TempDir, Kube) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), "t0ken\n").unwrap();
        let cfg = KubeConfig { api: "https://127.0.0.1:1".into(), token_file: dir.path().join("token"), ca_file: None };
        (dir, Kube::new(&cfg, Duration::from_secs(1)).unwrap())
    }

    #[test]
    fn paths_are_built_from_valid_names_only() {
        let (_d, k) = client();
        assert_eq!(k.path(VESSELS, None, None).unwrap(), "/apis/taso.suocommerce.com/v1alpha1/vessels");
        assert_eq!(k.path(VESSELS, Some("team-a"), Some("v1")).unwrap(), "/apis/taso.suocommerce.com/v1alpha1/namespaces/team-a/vessels/v1");
        let core = Resource { group: "", version: "v1", plural: "namespaces" };
        assert_eq!(k.path(core, None, Some("team-a")).unwrap(), "/api/v1/namespaces/team-a");
        for (ns, name) in [(Some("../kube-system"), None), (Some("a"), Some("x/../../secrets")), (Some("A"), None)] {
            assert!(matches!(k.path(VESSELS, ns, name), Err(KubeError::BadName(_))), "{ns:?} {name:?}");
        }
        // And a bad name is refused before any request (no network needed).
        assert!(matches!(k.get(VESSELS, "a", "b/c"), Err(KubeError::BadName(_))));
        assert!(matches!(k.patch_status(VESSELS, "ns/x", "b", &Value::Null), Err(KubeError::BadName(_))));
        assert!(matches!(k.patch_status_at(VESSELS, "a", "b", Some(""), &Value::Null), Err(KubeError::BadName(_))));
    }

    #[test]
    fn only_https_is_accepted() {
        for api in ["http://10.0.0.1:443", "10.0.0.1:443", "https://", "ftp://x"] {
            let cfg = KubeConfig { api: api.into(), token_file: "/t".into(), ca_file: None };
            assert!(Kube::new(&cfg, Duration::from_secs(1)).is_err(), "{api}");
        }
    }

    #[test]
    fn in_cluster_parts() {
        let dir = Path::new("/sa");
        let c = KubeConfig::from_parts("10.96.0.1", "443", dir).unwrap();
        assert_eq!(c, KubeConfig { api: "https://10.96.0.1:443".into(), token_file: "/sa/token".into(), ca_file: Some("/sa/ca.crt".into()) });
        assert_eq!(KubeConfig::from_parts("fd00::1", "443", dir).unwrap().api, "https://[fd00::1]:443");
        for (h, p) in [("", "443"), ("a/b", "443"), ("x@y", "443"), ("h", "0"), ("h", "99999"), ("h", "x")] {
            assert!(KubeConfig::from_parts(h, p, dir).is_err(), "{h:?}:{p:?}");
        }
    }

    #[test]
    fn the_token_is_read_each_time_and_must_be_one_line() {
        let (dir, k) = client();
        assert_eq!(k.token().unwrap(), "t0ken");
        std::fs::write(dir.path().join("token"), "rotated").unwrap();
        assert_eq!(k.token().unwrap(), "rotated", "a rotated token is used at once");
        for bad in ["", "\n", "two\nlines"] {
            std::fs::write(dir.path().join("token"), bad).unwrap();
            assert!(matches!(k.token(), Err(KubeError::Token(_))), "{bad:?}");
        }
        std::fs::remove_file(dir.path().join("token")).unwrap();
        assert!(matches!(k.token(), Err(KubeError::Token(_))));
    }

    #[test]
    fn error_answers_keep_the_servers_reason() {
        let e = status_error(404, r#"{"kind":"Status","status":"Failure","reason":"NotFound","message":"vessels.taso.suocommerce.com \"x\" not found","code":404}"#);
        assert!(e.is_not_found());
        assert!(e.to_string().contains("404 NotFound"), "{e}");
        let e = status_error(502, "<html>bad gateway</html>");
        assert!(matches!(&e, KubeError::Status { code: 502, reason, message } if reason.is_empty() && message.contains("bad gateway")));
        assert!(!e.is_not_found());
    }

    #[test]
    fn no_answer_is_a_transport_error() {
        // Port 1 on localhost: nothing listens.
        let (_d, k) = client();
        assert!(matches!(k.list(VESSELS, None, None), Err(KubeError::Transport(_))));
    }

    /// Against a real API server with the Vessel CRD applied: set
    /// TASO_KUBE_API (https://…), TASO_KUBE_TOKEN_FILE, TASO_KUBE_CA
    /// (optional), and TASO_KUBE_VESSEL=<namespace>/<name> of an existing
    /// Vessel whose status this test may write.
    #[test]
    #[ignore = "needs a kube-apiserver: set TASO_KUBE_*"]
    fn against_a_real_api_server() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let cfg = KubeConfig {
            api: env("TASO_KUBE_API"),
            token_file: env("TASO_KUBE_TOKEN_FILE").into(),
            ca_file: std::env::var_os("TASO_KUBE_CA").map(Into::into),
        };
        let k = Kube::new(&cfg, Duration::from_secs(10)).unwrap();
        let target = env("TASO_KUBE_VESSEL");
        let (ns, name) = target.split_once('/').unwrap();

        let all = k.list(VESSELS, None, None).unwrap();
        assert_eq!(all["kind"], "VesselList");
        assert!(all["items"].as_array().unwrap().iter().any(|v| v["metadata"]["name"] == name), "{all}");
        let in_ns = k.list(VESSELS, Some(ns), None).unwrap();
        assert!(!in_ns["items"].as_array().unwrap().is_empty());

        let v = k.get(VESSELS, ns, name).unwrap();
        assert_eq!(v["metadata"]["name"], name);

        let after = k.patch_status(VESSELS, ns, name, &serde_json::json!({ "phase": "Pending", "message": "from the kube client test" })).unwrap();
        assert_eq!(after["status"]["phase"], "Pending");
        assert_eq!(after["status"]["message"], "from the kube client test");
        assert_eq!(after["spec"], v["spec"], "a status patch leaves spec alone");

        let missing = k.get(VESSELS, ns, "no-such-vessel").unwrap_err();
        assert!(missing.is_not_found(), "{missing}");
        // At a resourceVersion: applied while it is current, refused after.
        let rv = after["metadata"]["resourceVersion"].as_str().unwrap().to_string();
        let at = k.patch_status_at(VESSELS, ns, name, Some(&rv), &serde_json::json!({ "message": "at rv" })).unwrap();
        assert_eq!(at["status"]["message"], "at rv");
        let stale = k.patch_status_at(VESSELS, ns, name, Some(&rv), &serde_json::json!({ "message": "stale" })).unwrap_err();
        assert!(matches!(stale, KubeError::Status { code: 409, .. }), "{stale}");
        assert_eq!(k.get(VESSELS, ns, name).unwrap()["status"]["message"], "at rv", "a stale patch writes nothing");
        let bad_phase = k.patch_status(VESSELS, ns, name, &serde_json::json!({ "phase": "Sleeping" })).unwrap_err();
        assert!(matches!(bad_phase, KubeError::Status { code: 422, .. }), "the CRD's enum is enforced: {bad_phase}");

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), "not-a-token").unwrap();
        let wrong = Kube::new(&KubeConfig { token_file: dir.path().join("t"), ..cfg.clone() }, Duration::from_secs(10)).unwrap();
        assert!(matches!(wrong.list(VESSELS, None, None), Err(KubeError::Status { code: 401, .. })));

        // The cluster's CA is private: the public roots alone do not trust it.
        if cfg.ca_file.is_some() {
            let public = Kube::new(&KubeConfig { ca_file: None, ..cfg.clone() }, Duration::from_secs(10)).unwrap();
            assert!(matches!(public.list(VESSELS, None, None), Err(KubeError::Transport(_))));
        }
    }
}
