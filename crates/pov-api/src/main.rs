use std::{error::Error, io, path::PathBuf};

#[cfg(unix)]
use std::{sync::Arc, time::SystemTime};

#[cfg(unix)]
use pov_api::{ApiGeneration, DEFAULT_BIND_ADDRESS, app_with_generation};
#[cfg(unix)]
use pov_core::{
    auth::{AuthRuntime, complete_operator_init, prepare_operator_init},
    generation_worker::spawn_generation_worker,
    loopback_llm::LoopbackLlmRuntime,
    storage::StoreSet,
};
#[cfg(unix)]
use tokio::net::TcpListener;

fn main() -> Result<(), Box<dyn Error>> {
    let command = parse_command(std::env::args_os().skip(1))?;
    match command {
        #[cfg(unix)]
        Command::Serve { instance_root } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(serve(instance_root)),
        #[cfg(unix)]
        Command::AuthInit {
            instance_root,
            login_id,
        } => {
            // Prompting and signal-mask coordination must finish on this original
            // single thread before Tokio is allowed to create worker threads.
            let confirmed =
                prepare_operator_init(&instance_root, &login_id, current_time_micros()?)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(complete_operator_init(confirmed))
                .map_err(Into::into)
        }
        #[cfg(not(unix))]
        _ => Err(io::Error::other("production authentication requires Unix").into()),
    }
}

#[cfg(unix)]
async fn serve(instance_root: PathBuf) -> Result<(), Box<dyn Error>> {
    let stores = Arc::new(StoreSet::open(instance_root.join("stores")).await?);
    let now_micros = current_time_micros()?;
    let runtime = Arc::new(AuthRuntime::open(&instance_root, stores.as_ref(), now_micros).await?);
    let listener = TcpListener::bind(DEFAULT_BIND_ADDRESS).await?;
    let generation_runtime = Arc::new(LoopbackLlmRuntime::from_environment(
        instance_root.join("runtime").join("llm"),
    ));
    let (generation_signal, generation_worker) =
        spawn_generation_worker(Arc::clone(&stores), Arc::clone(&generation_runtime));
    let server_result = axum::serve(
        listener,
        app_with_generation(
            Arc::clone(&runtime),
            Arc::clone(&stores),
            ApiGeneration::new(Arc::clone(&generation_runtime), generation_signal),
        ),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    let worker_result = generation_worker.shutdown().await;
    server_result?;
    worker_result?;
    drop(generation_runtime);
    drop(runtime);
    let stores = Arc::try_unwrap(stores)
        .map_err(|_| io::Error::other("store references remain after server shutdown"))?;
    stores.close().await?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Serve {
        instance_root: PathBuf,
    },
    AuthInit {
        instance_root: PathBuf,
        login_id: String,
    },
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: pov-api --instance-root <path> | pov-api auth init --instance-root <path> --login-id <id>",
    )
}

fn parse_command(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Command, io::Error> {
    let first = arguments.next().ok_or_else(usage)?;
    if first == "--instance-root" {
        let root = arguments.next().ok_or_else(usage)?;
        if root.is_empty() || arguments.next().is_some() {
            return Err(usage());
        }
        return Ok(Command::Serve {
            instance_root: root.into(),
        });
    }
    if first != "auth"
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("init"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--instance-root"))
    {
        return Err(usage());
    }
    let root = arguments.next().ok_or_else(usage)?;
    if root.is_empty() || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--login-id")) {
        return Err(usage());
    }
    let login = arguments.next().ok_or_else(usage)?;
    if login.is_empty() || arguments.next().is_some() {
        return Err(usage());
    }
    let login_id = login.into_string().map_err(|_| usage())?;
    Ok(Command::AuthInit {
        instance_root: root.into(),
        login_id,
    })
}

#[cfg(unix)]
fn current_time_micros() -> Result<u64, io::Error> {
    let micros = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
        .as_micros();
    u64::try_from(micros).map_err(|_| io::Error::other("system clock is out of range"))
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_command};

    #[test]
    fn production_instance_root_is_explicit_and_exact() {
        assert_eq!(
            parse_command(
                ["--instance-root", "/tmp/pov-instance"]
                    .into_iter()
                    .map(Into::into)
            )
            .expect("explicit root"),
            Command::Serve {
                instance_root: std::path::PathBuf::from("/tmp/pov-instance")
            }
        );
        assert_eq!(
            parse_command(
                [
                    "auth",
                    "init",
                    "--instance-root",
                    "/tmp/pov-instance",
                    "--login-id",
                    "owner_01"
                ]
                .into_iter()
                .map(Into::into)
            )
            .unwrap(),
            Command::AuthInit {
                instance_root: "/tmp/pov-instance".into(),
                login_id: "owner_01".into()
            }
        );
        for arguments in [
            Vec::<std::ffi::OsString>::new(),
            vec!["/tmp/pov-instance".into()],
            vec!["--instance-root".into()],
            vec!["--instance-root".into(), "".into()],
            vec![
                "--instance-root".into(),
                "/tmp/pov-instance".into(),
                "extra".into(),
            ],
        ] {
            assert!(parse_command(arguments.into_iter()).is_err());
        }
        for forbidden in [
            vec![
                "auth",
                "init",
                "--instance-root",
                "/tmp/x",
                "--login-id",
                "owner",
                "--password",
                "secret",
            ],
            vec![
                "auth",
                "init",
                "--instance-root",
                "/tmp/x",
                "--login-id",
                "owner",
                "secret",
            ],
        ] {
            assert!(parse_command(forbidden.into_iter().map(Into::into)).is_err());
        }
    }
}
