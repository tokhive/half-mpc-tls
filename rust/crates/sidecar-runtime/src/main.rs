use std::{env, path::PathBuf, process::ExitCode, sync::Arc};

use tokenhive_sidecar::{ReloadingFileCredentialResolver, ServiceError, SidecarServer};
use tokenhive_sidecar_protocol::{MpcCapacity, Role};

struct Config {
    role: Role,
    socket: PathBuf,
    credential_file: Option<PathBuf>,
    upstream_ca: Option<PathBuf>,
    capacity: MpcCapacity,
    tls13: bool,
}

fn parse_args() -> Result<Config, &'static str> {
    parse_args_from(env::args_os().skip(1))
}

fn parse_args_from(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Config, &'static str> {
    let mut role = None;
    let mut socket = None;
    let mut credential_file = None;
    let mut upstream_ca = None;
    let mut capacity = None;
    let mut tls13 = false;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--role") => {
                let value = arguments.next().ok_or("--role requires a value")?;
                role = Some(match value.to_str() {
                    Some("hub") => Role::Hub,
                    Some("provider") => Role::Provider,
                    _ => return Err("--role must be hub or provider"),
                });
            }
            Some("--socket") => {
                socket = Some(PathBuf::from(
                    arguments.next().ok_or("--socket requires a value")?,
                ));
            }
            Some("--credential-file") => {
                credential_file = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--credential-file requires a value")?,
                ));
            }
            Some("--upstream-ca") => {
                upstream_ca = Some(PathBuf::from(
                    arguments.next().ok_or("--upstream-ca requires a value")?,
                ));
            }
            Some("--tls-version") => {
                tls13 = match arguments
                    .next()
                    .and_then(|s| s.into_string().ok())
                    .as_deref()
                {
                    Some("1.2") => false,
                    Some("1.3") => true,
                    _ => return Err("--tls-version must be 1.2 or 1.3"),
                };
            }
            Some("--capacity") => {
                let value = arguments.next().ok_or("--capacity requires a value")?;
                capacity = Some(
                    value
                        .to_str()
                        .and_then(MpcCapacity::from_profile)
                        .ok_or("--capacity must be baseline, 16k, 64k, 256k, 1m or 5m")?,
                );
            }
            Some("--help") | Some("-h") => {
                return Err(
                    "usage: tokenhive-sidecar --role hub|provider --socket PATH [--credential-file PATH] [--upstream-ca PEM_FILE] [--capacity baseline|16k|64k|256k|1m|5m] [--tls-version 1.2|1.3]",
                );
            }
            _ => return Err("unknown argument"),
        }
    }
    let role = role.ok_or("--role is required")?;
    if role == Role::Hub && credential_file.is_some() {
        return Err("--credential-file is Provider-only");
    }
    Ok(Config {
        role,
        socket: socket.ok_or("--socket is required")?,
        credential_file,
        upstream_ca,
        capacity: capacity.unwrap_or_else(|| {
            if tls13 {
                MpcCapacity::large()
            } else {
                MpcCapacity::baseline()
            }
        }),
        tls13,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tokenhive-sidecar: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args().map_err(io_error)?;
    let mut credential_reloader = None;
    let server = match config.credential_file {
        Some(path) => {
            let resolver = Arc::new(ReloadingFileCredentialResolver::load(path)?);
            credential_reloader = Some(Arc::clone(&resolver));
            SidecarServer::bind_with_credential_resolver_and_capacity(
                config.socket,
                config.role,
                resolver,
                config.capacity,
            )?
        }
        None => SidecarServer::bind_with_capacity(config.socket, config.role, config.capacity)?,
    };
    let server = match config.upstream_ca {
        Some(path) => server.with_upstream_ca(path)?,
        None => server,
    };
    let server = if config.tls13 {
        server.with_tls13()
    } else {
        server
    };
    // Register before accepting clients so SIGTERM always performs socket cleanup.
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    server
        .run(shutdown_signal(credential_reloader, terminate))
        .await?;
    Ok(())
}

async fn shutdown_signal(
    reloader: Option<Arc<ReloadingFileCredentialResolver>>,
    mut terminate: tokio::signal::unix::Signal,
) {
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("tokenhive-sidecar: failed to listen for SIGHUP: {error}");
            let _ = interrupt.await;
            return;
        }
    };
    loop {
        tokio::select! {
            _ = terminate.recv() => return,
            result = &mut interrupt => {
                if let Err(error) = result {
                    eprintln!("tokenhive-sidecar: failed to listen for shutdown: {error}");
                }
                return;
            }
            signal = hangup.recv() => {
                if signal.is_none() {
                    return;
                }
                if let Some(resolver) = &reloader {
                    match resolver.reload() {
                        Ok(generation) => eprintln!("tokenhive-sidecar: credential snapshot reloaded (generation {generation})"),
                        Err(error) => eprintln!("tokenhive-sidecar: credential reload rejected; retaining previous snapshot: {error}"),
                    }
                }
            }
        }
    }
}

fn io_error(message: &'static str) -> ServiceError {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_uses_one_shared_profile_and_preserves_explicit_legacy_capacity() {
        for (flags, expected) in [
            (vec![], MpcCapacity::baseline()),
            (vec!["--tls-version", "1.3"], MpcCapacity::large()),
            (
                vec!["--capacity", "baseline", "--tls-version", "1.3"],
                MpcCapacity::baseline(),
            ),
            (
                vec!["--tls-version", "1.3", "--capacity", "16k"],
                MpcCapacity::from_profile("16k").unwrap(),
            ),
        ] {
            let args = [vec!["--role", "hub", "--socket", "/tmp/unused.sock"], flags].concat();
            let config = parse_args_from(args.into_iter().map(std::ffi::OsString::from)).unwrap();
            assert_eq!(config.capacity, expected);
        }
    }
}
