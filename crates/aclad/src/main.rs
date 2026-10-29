use aclad::acl::LibAclBackend;
use aclad::dbus::{BUS_NAME, Manager, OBJECT_PATH};
use aclad::grant::{FsGrantStore, default_grant_dir};
use aclad::service::Service;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use zbus::connection::Builder;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Bus {
    System,
    Session,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, value_enum, default_value_t = Bus::System)]
    bus: Bus,
    #[arg(long, default_value_os_t = default_grant_dir().to_path_buf())]
    grant_dir: PathBuf,
    #[arg(long, default_value = "/run/udev/static_node-tags/uaccess")]
    static_tag_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Without an explicit default, an unset RUST_LOG means "error only",
    // which leaves a supervised daemon with an empty log and nothing to
    // diagnose a live failure with.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aclad=info".into()),
        )
        .init();
    let args = Args::parse();
    anyhow::ensure!(unsafe { libc::geteuid() } == 0, "aclad must run as root");

    let (devices, mut events) = aclad::monitor::spawn()?;
    let service = Arc::new(Service::load(
        Arc::new(FsGrantStore::new(args.grant_dir)),
        Arc::new(LibAclBackend::new(args.static_tag_dir)),
        devices,
    )?);
    let builder = match args.bus {
        Bus::System => Builder::system(),
        Bus::Session => Builder::session(),
    };
    // The builder always sets DO_NOT_QUEUE; turning the other two flags
    // off means a second instance fails to start instead of silently
    // stealing the name from the running daemon (which would then keep
    // running unreachable, with the supervisor none the wiser).
    let connection = builder
        .name(BUS_NAME)
        .allow_name_replacements(false)
        .replace_existing_names(false)
        .serve_at(OBJECT_PATH, Manager::new(service.clone()))
        .build()
        .await
        .map_err(|error| match error {
            zbus::Error::NameTaken => {
                anyhow::anyhow!("{BUS_NAME} is already owned on this bus; another aclad is running")
            }
            other => anyhow::Error::new(other),
        })?;

    let integration_bus = match args.bus {
        Bus::System => aclad::sessiond::Bus::System,
        Bus::Session => aclad::sessiond::Bus::Session,
    };
    let integrated = aclad::sessiond::start(integration_bus, service.clone())?;
    tracing::info!(sessiond_integration = integrated, "aclad ready");

    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(event) => service.handle_event(event)?,
                None => anyhow::bail!("udev monitor ended"),
            },
            // Grants outlive us on disk, so exiting here is safe: the
            // supervisor restarts us and `Service::load` reloads them.
            // Staying alive without a name would silently strip every
            // future session of device access instead.
            () = connection.closed() => anyhow::bail!("lost the D-Bus connection"),
        }
    }
}
