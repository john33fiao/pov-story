use std::{error::Error, io, path::PathBuf, sync::Arc, time::SystemTime};

#[cfg(unix)]
use pov_api::{DEFAULT_BIND_ADDRESS, app_with_auth};
#[cfg(unix)]
use pov_core::{
    auth::{AuthRuntime, run_operator_init},
    storage::StoreSet,
};
#[cfg(unix)]
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    run().await
}

#[cfg(unix)]
async fn run() -> Result<(), Box<dyn Error>> {
    let command = parse_command(std::env::args_os().skip(1))?;
    let instance_root = match command {
        Command::Serve { instance_root } => instance_root,
        Command::AuthInit {
            instance_root,
            login_id,
        } => {
            return run_operator_init(&instance_root, &login_id, current_time_micros()?)
                .await
                .map_err(Into::into);
        }
    };
    let stores = StoreSet::open(instance_root.join("stores")).await?;
    let now_micros = current_time_micros()?;
    let runtime = Arc::new(AuthRuntime::open(&instance_root, &stores, now_micros).await?);
    let listener = TcpListener::bind(DEFAULT_BIND_ADDRESS).await?;
    axum::serve(listener, app_with_auth(runtime)).await?;
    stores.close().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn run() -> Result<(), Box<dyn Error>> {
    Err(io::Error::other("production authentication requires Unix").into())
}

#[cfg(unix)]
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

#[cfg(all(test, unix))]
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
