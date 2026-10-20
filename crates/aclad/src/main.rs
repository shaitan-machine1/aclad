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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
    let connection = builder
        .name(BUS_NAME)
        .serve_at(OBJECT_PATH, Manager::new(service.clone()))
        .build()
        .await?;

    let integrated = aclad::sessiond::start(connection.clone(), service.clone()).await?;
    tracing::info!(sessiond_integration = integrated, "aclad ready");

    while let Some(event) = events.recv().await {
        service.handle_event(event)?;
    }
    anyhow::bail!("udev monitor ended")
}
