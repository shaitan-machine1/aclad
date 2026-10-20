use crate::service::Service;
use futures_util::StreamExt;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use zbus::Connection;

#[zbus::proxy(
    interface = "org.decoupling.sessiond1.Manager",
    default_service = "org.decoupling.sessiond1",
    default_path = "/org/decoupling/sessiond1"
)]
trait Sessiond {
    fn list_sessions(&self) -> zbus::Result<Vec<(String, u32)>>;
    #[zbus(signal)]
    fn session_removed(&self, sid: &str, uid: u32) -> zbus::Result<()>;
}

/// Subscribe before listing so removal cannot be lost in the startup window.
/// Returns false when sessiond is initially absent; persisted PAM-only grants
/// are retained and periodic reconciliation attaches if sessiond appears later.
pub async fn start(connection: Connection, service: Arc<Service>) -> anyhow::Result<bool> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = monitor(connection, service, ready_tx).await;
        if let Err(error) = result {
            tracing::error!(%error, "sessiond integration ended");
        }
    });
    ready_rx
        .await
        .map_err(|_| anyhow::anyhow!("sessiond monitor failed to initialize"))?
}

async fn monitor(
    connection: Connection,
    service: Arc<Service>,
    ready: tokio::sync::oneshot::Sender<anyhow::Result<bool>>,
) -> anyhow::Result<()> {
    let proxy = SessiondProxy::new(&connection).await?;
    let mut removed = proxy.receive_session_removed().await?;
    let initial = reconcile(&proxy, &service).await;
    match initial {
        Ok(()) => {
            let _ = ready.send(Ok(true));
        }
        Err(error) => {
            tracing::debug!(%error, "sessiond unavailable; retaining persisted grants");
            let _ = ready.send(Ok(false));
        }
    }

    let mut retry = tokio::time::interval(Duration::from_secs(5));
    retry.tick().await;
    loop {
        tokio::select! {
            signal = removed.next() => {
                let Some(signal) = signal else { anyhow::bail!("SessionRemoved stream ended"); };
                match signal.args() {
                    Ok(args) => {
                        if let Err(error) = service.revoke(args.sid()) {
                            tracing::error!(sid = args.sid(), %error, "SessionRemoved revoke failed");
                        }
                    }
                    Err(error) => tracing::warn!(%error, "invalid SessionRemoved signal"),
                }
            }
            _ = retry.tick() => {
                if let Err(error) = reconcile(&proxy, &service).await {
                    tracing::debug!(%error, "periodic sessiond reconciliation unavailable");
                }
            }
        }
    }
}

async fn reconcile(proxy: &SessiondProxy<'_>, service: &Service) -> anyhow::Result<()> {
    let sessions = proxy.list_sessions().await?;
    let live = sessions
        .into_iter()
        .map(|(sid, _)| sid)
        .collect::<BTreeSet<_>>();
    service.reconcile_sessions(&live)
}
