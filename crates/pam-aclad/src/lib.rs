use libc::{LOG_ERR, c_char, c_int, c_void};
use pam_ffi::{PAM_OPEN_ERR, PAM_SESSION_ERR, PAM_SUCCESS, PAM_TTY, PAM_USER_UNKNOWN, PamHandle};
use seat_udev::SeatName;
use std::ffi::{CStr, CString};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::time::Duration;

#[zbus::proxy(
    interface = "org.decoupling.aclad1.Manager",
    default_service = "org.decoupling.aclad1",
    default_path = "/org/decoupling/aclad1"
)]
trait Aclad {
    fn grant(&self, sid: &str, uid: u32, seat: &str) -> zbus::Result<()>;
    fn revoke(&self, sid: &str) -> zbus::Result<()>;
}

struct ModuleData {
    sid: CString,
}

struct Failure {
    status: c_int,
    message: String,
}

impl Failure {
    fn new(status: c_int, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn emit_message(message: &str, mut logger: impl FnMut(&str)) {
    logger(message);
}

unsafe fn log_error(pamh: *mut PamHandle, message: &str) {
    // SAFETY: PAM supplies a live, non-null handle to every module entry point.
    if let Some(handle) = unsafe { pamh.as_ref() } {
        emit_message(message, |message| pam_ffi::syslog(handle, LOG_ERR, message));
    }
}

unsafe extern "C" fn cleanup_data(_pamh: *mut PamHandle, data: *mut c_void, _status: c_int) {
    if !data.is_null() {
        // SAFETY: pointer was created by Box::into_raw and PAM calls cleanup once.
        drop(unsafe { Box::from_raw(data.cast::<ModuleData>()) });
    }
}

/// Linux-PAM session-open entry point.
///
/// # Safety
/// PAM must pass a live `pamh` and a valid `argv` array of `argc` C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        open_session(pamh, parse_timeout(argc, argv))
    })) {
        Ok(status) => status,
        Err(_) => {
            // SAFETY: forwarded live PAM handle.
            unsafe { log_error(pamh, "panic while opening a session through pam_aclad") };
            PAM_OPEN_ERR
        }
    }
}

/// Linux-PAM session-close entry point.
///
/// # Safety
/// PAM must pass a live `pamh` and a valid `argv` array of `argc` C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        close_session(pamh, parse_timeout(argc, argv))
    })) {
        Ok(status) => status,
        Err(_) => {
            // SAFETY: forwarded live PAM handle.
            unsafe { log_error(pamh, "panic while closing a session through pam_aclad") };
            PAM_SESSION_ERR
        }
    }
}

fn open_session(pamh: *mut PamHandle, timeout: Duration) -> c_int {
    match open_inner(pamh, timeout) {
        Ok(()) => PAM_SUCCESS,
        Err(failure) => {
            // SAFETY: pamh is live for this module call.
            unsafe { log_error(pamh, &failure.message) };
            failure.status
        }
    }
}

fn open_inner(pamh: *mut PamHandle, timeout: Duration) -> Result<(), Failure> {
    let seat = match determine_seat(pamh)? {
        Some(seat) => seat,
        None => return Ok(()),
    };
    // SAFETY: pamh is live for this module call.
    let sid = unsafe { pam_ffi::get_env(pamh, c"XDG_SESSION_ID") }.ok_or_else(|| {
        Failure::new(
            PAM_SESSION_ERR,
            "XDG_SESSION_ID is absent; pam_sessiond must run before pam_aclad",
        )
    })?;
    // SAFETY: pamh is live for this module call.
    let user = unsafe { pam_ffi::get_user(pamh) }.map_err(|status| {
        Failure::new(
            status,
            format!("pam_get_user failed with PAM status {status}"),
        )
    })?;
    let uid = lookup_uid(&user)
        .map_err(|error| Failure::new(PAM_SESSION_ERR, format!("look up user {user:?}: {error}")))?
        .ok_or_else(|| Failure::new(PAM_USER_UNKNOWN, format!("user {user:?} does not exist")))?;
    call(
        timeout,
        Operation::Grant {
            sid: sid.clone(),
            uid,
            seat: seat.to_string(),
        },
    )
    .map_err(|error| Failure::new(PAM_SESSION_ERR, error))?;

    let sid_c = match CString::new(sid.clone()) {
        Ok(sid) => sid,
        Err(_) => {
            if let Err(error) = call(timeout, Operation::Revoke { sid: sid.clone() }) {
                // SAFETY: pamh is live for this module call.
                unsafe {
                    log_error(
                        pamh,
                        &format!("failed to roll back ACL grant for session {sid}: {error}"),
                    )
                };
            }
            return Err(Failure::new(
                PAM_SESSION_ERR,
                "XDG_SESSION_ID contains an interior NUL byte",
            ));
        }
    };
    let data = Box::new(ModuleData { sid: sid_c });
    let raw = Box::into_raw(data);
    // SAFETY: ownership transfers to PAM on success.
    if let Err(status) =
        unsafe { pam_ffi::set_data(pamh, c"pam_aclad.grant", raw.cast(), cleanup_data) }
    {
        // SAFETY: PAM rejected ownership.
        drop(unsafe { Box::from_raw(raw) });
        if let Err(error) = call(timeout, Operation::Revoke { sid: sid.clone() }) {
            // SAFETY: pamh is live for this module call.
            unsafe {
                log_error(
                    pamh,
                    &format!("failed to roll back ACL grant for session {sid}: {error}"),
                )
            };
        }
        return Err(Failure::new(
            status,
            format!("pam_set_data failed for ACL grant {sid} with PAM status {status}"),
        ));
    }
    Ok(())
}

fn close_session(pamh: *mut PamHandle, timeout: Duration) -> c_int {
    // SAFETY: pamh is live and data is owned by this PAM transaction.
    let data = match unsafe { pam_ffi::get_data(pamh, c"pam_aclad.grant") } {
        Ok(data) if !data.is_null() => data.cast::<ModuleData>(),
        _ => return PAM_SUCCESS,
    };
    // SAFETY: cleanup has not run while this PAM callback is active.
    let sid = unsafe { &*data }.sid.to_string_lossy().into_owned();
    match call(timeout, Operation::Revoke { sid }) {
        Ok(()) => PAM_SUCCESS,
        Err(error) => {
            // SAFETY: pamh is live for this module call.
            unsafe { log_error(pamh, &error) };
            PAM_SESSION_ERR
        }
    }
}

fn determine_seat(pamh: *mut PamHandle) -> Result<Option<SeatName>, Failure> {
    // SAFETY: pamh is live.
    if let Some(value) = unsafe { pam_ffi::get_env(pamh, c"XDG_SEAT") } {
        return SeatName::parse(&value).map(Some).map_err(|error| {
            Failure::new(
                PAM_SESSION_ERR,
                format!("invalid XDG_SEAT value {value:?}: {error}"),
            )
        });
    }
    // SAFETY: PAM_TTY is a string-valued item on a live handle.
    let tty = unsafe { pam_ffi::get_string_item(pamh, PAM_TTY) }.map_err(|status| {
        Failure::new(
            status,
            format!("pam_get_item(PAM_TTY) failed with PAM status {status}"),
        )
    })?;
    Ok(tty.filter(|tty| linux_vt(tty)).map(|_| SeatName::seat0()))
}

fn linux_vt(tty: &str) -> bool {
    let tty = tty.strip_prefix("/dev/").unwrap_or(tty);
    tty.strip_prefix("tty").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn lookup_uid(name: &str) -> Result<Option<u32>, String> {
    let name = CString::new(name).map_err(|_| "username contains an interior NUL byte")?;
    // SAFETY: passwd is a plain C result structure initialized before use.
    let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = ptr::null_mut();
    // SAFETY: sysconf has no pointer preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer = vec![0u8; if size > 0 { size as usize } else { 16 * 1024 }];
    // SAFETY: all pointers reference writable storage for this call.
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status).to_string());
    }
    Ok((!result.is_null()).then_some(passwd.pw_uid))
}

enum Operation {
    Grant { sid: String, uid: u32, seat: String },
    Revoke { sid: String },
}

impl Operation {
    fn description(&self) -> String {
        match self {
            Self::Grant { sid, uid, seat } => {
                format!("aclad Grant for session {sid}, uid {uid}, seat {seat}")
            }
            Self::Revoke { sid } => format!("aclad Revoke for session {sid}"),
        }
    }
}

fn call(timeout: Duration, operation: Operation) -> Result<(), String> {
    let description = operation.description();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create PAM async runtime for {description}: {error}"))?;
    runtime.block_on(async move {
        let timeout_description = description.clone();
        tokio::time::timeout(timeout, async move {
            let connection = zbus::Connection::system()
                .await
                .map_err(|error| format!("connect to the system bus for {description}: {error}"))?;
            let proxy = AcladProxy::new(&connection)
                .await
                .map_err(|error| format!("create aclad proxy for {description}: {error}"))?;
            match operation {
                Operation::Grant { sid, uid, seat } => proxy
                    .grant(&sid, uid, &seat)
                    .await
                    .map_err(|error| format!("aclad Grant for session {sid}: {error}")),
                Operation::Revoke { sid } => proxy
                    .revoke(&sid)
                    .await
                    .map_err(|error| format!("aclad Revoke for session {sid}: {error}")),
            }
        })
        .await
        .map_err(|_| format!("{timeout_description} timed out after {timeout:?}"))?
    })
}

fn parse_timeout(argc: c_int, argv: *const *const c_char) -> Duration {
    let mut timeout = Duration::from_secs(30);
    if argc <= 0 || argv.is_null() {
        return timeout;
    }
    for index in 0..argc as isize {
        // SAFETY: PAM supplies argc readable argument pointers.
        let argument = unsafe { *argv.offset(index) };
        if argument.is_null() {
            continue;
        }
        // SAFETY: each PAM argument is NUL terminated.
        let argument = unsafe { CStr::from_ptr(argument) }.to_string_lossy();
        if let Some(value) = argument.strip_prefix("timeout=")
            && let Some(parsed) = parse_duration(value)
        {
            timeout = parsed;
        }
    }
    timeout
}

fn parse_duration(value: &str) -> Option<Duration> {
    if let Some(value) = value.strip_suffix("ms") {
        value.parse().ok().map(Duration::from_millis)
    } else if let Some(value) = value.strip_suffix('s') {
        value.parse().ok().map(Duration::from_secs)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_linux_vts_imply_seat0() {
        assert!(linux_vt("tty1"));
        assert!(linux_vt("/dev/tty63"));
        assert!(!linux_vt("pts/1"));
        assert!(!linux_vt("tty"));
        assert!(!linux_vt("ttyS0"));
    }

    #[test]
    fn failure_message_reaches_logger_unchanged() {
        let mut logged = String::new();
        emit_message("aclad Grant for session abc: unavailable", |message| {
            logged = message.to_owned();
        });
        assert_eq!(logged, "aclad Grant for session abc: unavailable");
    }
}
