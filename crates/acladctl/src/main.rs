use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use seat_udev::SeatName;
use std::fmt::Write;
use std::process::ExitCode;

#[zbus::proxy(
    interface = "org.decoupling.aclad1.Manager",
    default_service = "org.decoupling.aclad1",
    default_path = "/org/decoupling/aclad1"
)]
trait Aclad {
    fn list_grants(&self) -> zbus::Result<Vec<(String, u32, String)>>;
    fn grant(&self, sid: &str, uid: u32, seat: &str) -> zbus::Result<()>;
    fn revoke(&self, sid: &str) -> zbus::Result<()>;
}

#[derive(Debug, Parser)]
#[command(version, about = "Inspect and administer aclad grants")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List active device ACL grants.
    List,
    /// Grant one user access to one seat for a session.
    Grant {
        #[arg(value_parser = parse_session_id)]
        sid: String,
        uid: u32,
        #[arg(value_parser = parse_seat)]
        seat: String,
    },
    /// Revoke a session's device ACL grant.
    Revoke {
        #[arg(value_parser = parse_session_id)]
        sid: String,
    },
}

fn parse_session_id(value: &str) -> std::result::Result<String, String> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value.to_owned())
    } else {
        Err("session ID must be exactly 32 lowercase hexadecimal digits".to_owned())
    }
}

fn parse_seat(value: &str) -> std::result::Result<String, String> {
    SeatName::parse(value)
        .map(|seat| seat.to_string())
        .map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("acladctl: create async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(Args::parse())) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("acladctl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<String> {
    let connection = zbus::Connection::system()
        .await
        .context("connect to the system bus")?;
    let proxy = AcladProxy::new(&connection)
        .await
        .context("create aclad D-Bus proxy")?;
    match args.command {
        Command::List => {
            let grants = proxy.list_grants().await.context("call aclad ListGrants")?;
            Ok(format_grants(&grants))
        }
        Command::Grant { sid, uid, seat } => {
            proxy.grant(&sid, uid, &seat).await.with_context(|| {
                format!("call aclad Grant for session {sid}, uid {uid}, seat {seat}")
            })?;
            Ok(format!(
                "Granted session {sid} to uid {uid} on seat {seat}.\n"
            ))
        }
        Command::Revoke { sid } => {
            proxy
                .revoke(&sid)
                .await
                .with_context(|| format!("call aclad Revoke for session {sid}"))?;
            Ok(format!("Revoked session {sid}.\n"))
        }
    }
}

fn format_grants(grants: &[(String, u32, String)]) -> String {
    if grants.is_empty() {
        return "No grants.\n".to_owned();
    }
    let session_width = grants
        .iter()
        .map(|(sid, _, _)| sid.len())
        .chain(["SESSION".len()])
        .max()
        .expect("heading provides a width");
    let uid_width = grants
        .iter()
        .map(|(_, uid, _)| uid.to_string().len())
        .chain(["UID".len()])
        .max()
        .expect("heading provides a width");
    let mut output = String::new();
    writeln!(
        output,
        "{:<session_width$}  {:>uid_width$}  SEAT",
        "SESSION", "UID"
    )
    .expect("writing to String cannot fail");
    for (sid, uid, seat) in grants {
        writeln!(output, "{sid:<session_width$}  {uid:>uid_width$}  {seat}")
            .expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "1123456789abcdef0123456789abcdef";

    #[test]
    fn parses_all_commands() {
        assert!(matches!(
            Args::try_parse_from(["acladctl", "list"])
                .expect("list parses")
                .command,
            Command::List
        ));
        let grant =
            Args::try_parse_from(["acladctl", "grant", A, "1000", "seat2"]).expect("grant parses");
        assert!(matches!(
            grant.command,
            Command::Grant { sid, uid: 1000, seat } if sid == A && seat == "seat2"
        ));
        let revoke = Args::try_parse_from(["acladctl", "revoke", A]).expect("revoke parses");
        assert!(matches!(revoke.command, Command::Revoke { sid } if sid == A));
    }

    #[test]
    fn rejects_malformed_arguments() {
        let sid = Args::try_parse_from(["acladctl", "revoke", "bad"])
            .expect_err("invalid session is rejected");
        assert_eq!(sid.kind(), ErrorKind::ValueValidation);
        let uid = Args::try_parse_from(["acladctl", "grant", A, "not-a-uid", "seat0"])
            .expect_err("invalid uid is rejected");
        assert_eq!(uid.kind(), ErrorKind::ValueValidation);
        let seat = Args::try_parse_from(["acladctl", "grant", A, "1000", "not/a/seat"])
            .expect_err("invalid seat is rejected");
        assert_eq!(seat.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn renders_empty_state() {
        assert_eq!(format_grants(&[]), "No grants.\n");
    }

    #[test]
    fn renders_aligned_table_without_reordering() {
        let output = format_grants(&[
            (B.to_owned(), 7, "seat-long".to_owned()),
            (A.to_owned(), 1000, "seat0".to_owned()),
        ]);
        assert_eq!(
            output,
            concat!(
                "SESSION                            UID  SEAT\n",
                "1123456789abcdef0123456789abcdef     7  seat-long\n",
                "0123456789abcdef0123456789abcdef  1000  seat0\n",
            )
        );
    }

    #[test]
    fn renders_contextual_dbus_errors() {
        let error = anyhow::anyhow!("org.decoupling.aclad1.Error.AccessDenied: root only")
            .context("call aclad ListGrants");
        assert_eq!(
            format!("{error:#}"),
            "call aclad ListGrants: org.decoupling.aclad1.Error.AccessDenied: root only"
        );
    }
}
