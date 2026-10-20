use libc::{c_char, c_int, c_void};
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
    catch_unwind(AssertUnwindSafe(|| {
        open_session(pamh, parse_timeout(argc, argv))
    }))
    .unwrap_or(PAM_OPEN_ERR)
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
    catch_unwind(AssertUnwindSafe(|| {
        close_session(pamh, parse_timeout(argc, argv))
    }))
    .unwrap_or(PAM_SESSION_ERR)
}

fn open_session(pamh: *mut PamHandle, timeout: Duration) -> c_int {
    let seat = match determine_seat(pamh) {
        Ok(Some(seat)) => seat,
        Ok(None) => return PAM_SUCCESS,
        Err(status) => return status,
    };
    // SAFETY: pamh is live for this module call.
    let sid = match unsafe { pam_ffi::get_env(pamh, c"XDG_SESSION_ID") } {
        Some(value) => value,
        None => return PAM_SESSION_ERR,
    };
    // SAFETY: pamh is live for this module call.
    let user = match unsafe { pam_ffi::get_user(pamh) } {
        Ok(user) => user,
        Err(status) => return status,
    };
    let uid = match lookup_uid(&user) {
        Some(uid) => uid,
        None => return PAM_USER_UNKNOWN,
    };
    if call(
        timeout,
        Operation::Grant {
            sid: sid.clone(),
            uid,
            seat: seat.to_string(),
        },
    )
    .is_err()
    {
        return PAM_SESSION_ERR;
    }
    let data = Box::new(ModuleData {
        sid: match CString::new(sid) {
            Ok(sid) => sid,
            Err(_) => return PAM_SESSION_ERR,
        },
    });
    let revoke_sid = data.sid.to_string_lossy().into_owned();
    let raw = Box::into_raw(data);
    // SAFETY: ownership transfers to PAM on success.
    if let Err(status) =
        unsafe { pam_ffi::set_data(pamh, c"pam_aclad.grant", raw.cast(), cleanup_data) }
    {
        // SAFETY: PAM rejected ownership.
        drop(unsafe { Box::from_raw(raw) });
        let _ = call(timeout, Operation::Revoke { sid: revoke_sid });
        return status;
    }
    PAM_SUCCESS
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
        Err(()) => PAM_SESSION_ERR,
    }
}

fn determine_seat(pamh: *mut PamHandle) -> Result<Option<SeatName>, c_int> {
    // SAFETY: pamh is live.
    if let Some(value) = unsafe { pam_ffi::get_env(pamh, c"XDG_SEAT") } {
        return SeatName::parse(value)
            .map(Some)
            .map_err(|_| PAM_SESSION_ERR);
    }
    // SAFETY: PAM_TTY is a string-valued item on a live handle.
    let tty = unsafe { pam_ffi::get_string_item(pamh, PAM_TTY) }?;
    Ok(tty.filter(|tty| linux_vt(tty)).map(|_| SeatName::seat0()))
}

fn linux_vt(tty: &str) -> bool {
    let tty = tty.strip_prefix("/dev/").unwrap_or(tty);
    tty.strip_prefix("tty").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn lookup_uid(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = ptr::null_mut();
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
    (status == 0 && !result.is_null()).then_some(passwd.pw_uid)
}

enum Operation {
    Grant { sid: String, uid: u32, seat: String },
    Revoke { sid: String },
}

fn call(timeout: Duration, operation: Operation) -> Result<(), ()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    runtime.block_on(async move {
        tokio::time::timeout(timeout, async move {
            let connection = zbus::Connection::system().await.map_err(|_| ())?;
            let proxy = AcladProxy::new(&connection).await.map_err(|_| ())?;
            match operation {
                Operation::Grant { sid, uid, seat } => {
                    proxy.grant(&sid, uid, &seat).await.map_err(|_| ())
                }
                Operation::Revoke { sid } => proxy.revoke(&sid).await.map_err(|_| ()),
            }
        })
        .await
        .map_err(|_| ())?
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
}
