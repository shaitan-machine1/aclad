use crate::service::Service;
use dbus::blocking::Connection;
use dbus::message::MatchRule;
use std::collections::BTreeSet;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const BUS_NAME: &str = "org.decoupling.sessiond1";
const OBJECT_PATH: &str = "/org/decoupling/sessiond1";
const INTERFACE: &str = "org.decoupling.sessiond1.Manager";
#[derive(Clone, Copy)]
pub enum Bus {
    System,
    Session,
}

/// Subscribe before querying so a removal cannot be lost in the startup
/// window. The signal rule intentionally has no sender constraint: lifecycle
/// signals can originate from root PAM connections as well as the daemon.
pub fn start(bus: Bus, service: Arc<Service>) -> anyhow::Result<bool> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("aclad-sessiond".into())
        .spawn(move || {
            if let Err(error) = monitor(bus, service, ready_tx) {
                tracing::error!(%error, "sessiond integration ended");
            }
        })?;
    ready_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("sessiond monitor failed to initialize"))?
}
fn monitor(
    bus: Bus,
    service: Arc<Service>,
    ready: mpsc::SyncSender<anyhow::Result<bool>>,
) -> anyhow::Result<()> {
    let connection = match bus {
        Bus::System => Connection::new_system()?,
        Bus::Session => Connection::new_session()?,
    };
    let mut rule = MatchRule::new_signal(INTERFACE, "SessionRemoved");
    rule.path = Some(OBJECT_PATH.into());
    let signal_service = service.clone();
    connection.add_match::<(String, u32), _>(rule, move |(sid, _), _, _| {
        if let Err(error) = signal_service.revoke(&sid) {
            tracing::error!(%sid, %error, "SessionRemoved revoke failed");
        }
        true
    })?;
    let initial = reconcile(&connection, &service);
    match initial {
        Ok(()) => {
            let _ = ready.send(Ok(true));
        }
        Err(error) => {
            tracing::debug!(%error, "sessiond unavailable; retaining persisted grants");
            let _ = ready.send(Ok(false));
        }
    }
    let mut next_reconcile = Instant::now() + Duration::from_secs(5);
    loop {
        connection.process(Duration::from_secs(1))?;
        if Instant::now() >= next_reconcile {
            if let Err(error) = reconcile(&connection, &service) {
                tracing::debug!(%error, "periodic sessiond reconciliation unavailable");
            }
            next_reconcile = Instant::now() + Duration::from_secs(5);
        }
    }
}
fn reconcile(connection: &Connection, service: &Service) -> anyhow::Result<()> {
    let proxy = connection.with_proxy(BUS_NAME, OBJECT_PATH, Duration::from_secs(5));
    let (sessions,): (Vec<(String, u32)>,) = proxy.method_call(INTERFACE, "ListSessions", ())?;
    let live = sessions
        .into_iter()
        .map(|(sid, _)| sid)
        .collect::<BTreeSet<_>>();
    service.reconcile_sessions(&live)
}
