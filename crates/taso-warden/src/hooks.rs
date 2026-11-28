//! Test hooks read from the environment (step 8, 8-10 (a), 2026-11-28).
//!
//! The gates stop a Warden or `taso-genesis` at a named point
//! (`TASO_FAILPOINT`), lose a reply on purpose (`TASO_LOSE_REPLY`), or pause
//! a Seal for the crash harness (`TASO_E3_HOLD`, `TASO_E3_HOLD_DIR`).  They
//! are read only in a build with the `test-hooks` feature, which the gates
//! that use them turn on.  In a release build a stray variable changes
//! nothing: [`env`] says once that it is ignored and answers `None`.

/// The value of the test hook `name` from the environment: with the
/// `test-hooks` feature, the variable if it is set; without it, always
/// `None`, and a line on stderr if the variable is set anyway.
pub fn env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    if cfg!(feature = "test-hooks") {
        return value;
    }
    if value.is_some() {
        eprintln!(
            "taso: {name} is set but ignored: this build has no test hooks (feature test-hooks)"
        );
    }
    None
}

/// As [`env`], for a path.
pub fn env_os(name: &str) -> Option<std::ffi::OsString> {
    let value = std::env::var_os(name);
    if cfg!(feature = "test-hooks") {
        return value;
    }
    if value.is_some() {
        eprintln!(
            "taso: {name} is set but ignored: this build has no test hooks (feature test-hooks)"
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without the feature a hook's variable is ignored; with it, it is
    /// read as it is.
    #[test]
    fn a_hook_is_read_only_with_the_feature() {
        std::env::set_var("TASO_HOOKS_PROBE", "x");
        let want = cfg!(feature = "test-hooks").then(|| "x".to_string());
        assert_eq!(env("TASO_HOOKS_PROBE"), want);
        assert_eq!(
            env_os("TASO_HOOKS_PROBE"),
            want.map(std::ffi::OsString::from)
        );
        std::env::remove_var("TASO_HOOKS_PROBE");
        assert_eq!(env("TASO_HOOKS_PROBE"), None);
    }
}
