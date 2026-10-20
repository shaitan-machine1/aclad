use seat_udev::{Context, Event, Filter, SeatDevice, SeatName};
use std::collections::BTreeSet;
use std::sync::mpsc;
use tokio::sync::mpsc as tokio_mpsc;

pub fn spawn() -> anyhow::Result<(Vec<SeatDevice>, tokio_mpsc::UnboundedReceiver<Event>)> {
    let (initial_tx, initial_rx) = mpsc::sync_channel(1);
    let (event_tx, event_rx) = tokio_mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("aclad-udev".into())
        .spawn(move || monitor_thread(initial_tx, event_tx))?;
    let initial = initial_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("udev monitor thread exited"))??;
    Ok((initial, event_rx))
}

fn monitor_thread(
    initial_tx: mpsc::SyncSender<anyhow::Result<Vec<SeatDevice>>>,
    event_tx: tokio_mpsc::UnboundedSender<Event>,
) {
    let mut context = match Context::new() {
        Ok(context) => context,
        Err(error) => {
            let _ = initial_tx.send(Err(error.into()));
            return;
        }
    };
    let mut seats: BTreeSet<_> = context.seats().into_iter().collect();
    seats.insert(SeatName::seat0());
    let initial = seats
        .iter()
        .flat_map(|seat| context.devices(seat, Filter::Uaccess))
        .collect();
    if initial_tx.send(Ok(initial)).is_err() {
        return;
    }

    loop {
        let mut descriptor = libc::pollfd {
            fd: context.monitor_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd.
        let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::error!(error = %std::io::Error::last_os_error(), "udev poll failed");
            return;
        }
        loop {
            match context.receive() {
                Ok(Some(events)) => {
                    for event in events {
                        if event_tx.send(event).is_err() {
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::error!(%error, "udev event failed");
                    break;
                }
            }
        }
    }
}
