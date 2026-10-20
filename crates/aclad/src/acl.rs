use anyhow::Context;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};

const ACL_TYPE_ACCESS: c_int = 0x8000;
type Acl = *mut c_void;

#[link(name = "acl")]
unsafe extern "C" {
    fn acl_get_file(path: *const c_char, acl_type: c_int) -> Acl;
    fn acl_from_text(text: *const c_char) -> Acl;
    fn acl_to_text(acl: Acl, length: *mut isize) -> *mut c_char;
    fn acl_calc_mask(acl: *mut Acl) -> c_int;
    fn acl_set_file(path: *const c_char, acl_type: c_int, acl: Acl) -> c_int;
    fn acl_free(object: *mut c_void) -> c_int;
}

pub trait AclBackend: Send + Sync {
    fn set_users(&self, path: &Path, users: &BTreeSet<u32>) -> anyhow::Result<()>;
    fn static_seat0_nodes(&self) -> anyhow::Result<Vec<PathBuf>>;
}

#[derive(Clone)]
pub struct LibAclBackend {
    static_tag_dir: PathBuf,
}

impl LibAclBackend {
    pub fn new(static_tag_dir: PathBuf) -> Self {
        Self { static_tag_dir }
    }
}

impl Default for LibAclBackend {
    fn default() -> Self {
        Self::new("/run/udev/static_node-tags/uaccess".into())
    }
}

impl AclBackend for LibAclBackend {
    fn set_users(&self, path: &Path, users: &BTreeSet<u32>) -> anyhow::Result<()> {
        set_users(path, users)
    }

    fn static_seat0_nodes(&self) -> anyhow::Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(&self.static_tag_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut nodes = Vec::new();
        for entry in entries {
            let entry = entry?;
            match std::fs::canonicalize(entry.path()) {
                Ok(path) => nodes.push(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(nodes)
    }
}

fn set_users(path: &Path, users: &BTreeSet<u32>) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes()).context("device path contains NUL")?;
    // SAFETY: path_c is NUL terminated and acl_get_file returns an owned ACL.
    let old = unsafe { acl_get_file(path_c.as_ptr(), ACL_TYPE_ACCESS) };
    if old.is_null() {
        return Err(std::io::Error::last_os_error()).with_context(|| path.display().to_string());
    }
    let mut length = 0isize;
    // SAFETY: old is a live ACL and text is released with acl_free below.
    let text = unsafe { acl_to_text(old, &mut length) };
    // SAFETY: old was returned by libacl.
    unsafe { acl_free(old) };
    if text.is_null() {
        return Err(std::io::Error::last_os_error()).context("serialize access ACL");
    }
    // SAFETY: acl_to_text returns a NUL-terminated string.
    let current = unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: text was allocated by libacl.
    unsafe { acl_free(text.cast()) };

    let rewritten = rewrite_acl(&current, users);
    let rewritten_c = CString::new(rewritten)?;
    // SAFETY: rewritten_c is a valid NUL-terminated ACL specification.
    let mut acl = unsafe { acl_from_text(rewritten_c.as_ptr()) };
    if acl.is_null() {
        return Err(std::io::Error::last_os_error()).context("parse rewritten access ACL");
    }
    // SAFETY: acl is owned and writable; libacl may replace it while calculating the mask.
    if unsafe { acl_calc_mask(&mut acl) } == -1 {
        let error = std::io::Error::last_os_error();
        // SAFETY: acl remains owned on failure.
        unsafe { acl_free(acl) };
        return Err(error).context("calculate access ACL mask");
    }
    // SAFETY: pointers are live for this call.
    let result = unsafe { acl_set_file(path_c.as_ptr(), ACL_TYPE_ACCESS, acl) };
    // SAFETY: acl is owned by this function.
    unsafe { acl_free(acl) };
    if result == -1 {
        return Err(std::io::Error::last_os_error()).with_context(|| path.display().to_string());
    }
    Ok(())
}

fn rewrite_acl(current: &str, users: &BTreeSet<u32>) -> String {
    let mut retained = Vec::new();
    let mut inserted = false;
    for line in current.lines().filter(|line| !line.trim().is_empty()) {
        let is_named_user = line
            .strip_prefix("user:")
            .and_then(|rest| rest.split(':').next())
            .is_some_and(|qualifier| !qualifier.is_empty());
        if is_named_user {
            continue;
        }
        if !inserted && line.starts_with("group:") {
            retained.extend(users.iter().map(|uid| format!("user:{uid}:rw-")));
            inserted = true;
        }
        // acl_calc_mask recomputes this entry.
        if !line.starts_with("mask:") {
            retained.push(line.to_owned());
        }
    }
    if !inserted {
        retained.extend(users.iter().map(|uid| format!("user:{uid}:rw-")));
    }
    retained.push(String::new());
    retained.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_all_named_users_and_preserves_other_entries() {
        let current =
            "user::rw-\nuser:1000:r--\ngroup::r--\ngroup:audio:rw-\nmask::rw-\nother::---\n";
        let users = BTreeSet::from([1001, 1002]);
        assert_eq!(
            rewrite_acl(current, &users),
            "user::rw-\nuser:1001:rw-\nuser:1002:rw-\ngroup::r--\ngroup:audio:rw-\nother::---\n"
        );
    }

    #[test]
    fn libacl_backend_adds_and_removes_named_users() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("aclad-acl-test-{}", std::process::id()));
        std::fs::write(&path, b"test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        set_users(&path, &BTreeSet::from([424_242])).unwrap();
        let output = std::process::Command::new("getfacl")
            .args(["-cp", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("user:424242:rw-")
        );
        set_users(&path, &BTreeSet::new()).unwrap();
        let output = std::process::Command::new("getfacl")
            .args(["-cp", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("user:424242:")
        );
        std::fs::remove_file(path).unwrap();
    }
}
