use std::{error::Error, io, path::PathBuf, sync::Arc, time::SystemTime};

#[cfg(unix)]
use pov_api::{DEFAULT_BIND_ADDRESS, app_with_auth};
#[cfg(unix)]
use pov_core::{auth::AuthRuntime, storage::StoreSet};
#[cfg(unix)]
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    run().await
}

#[cfg(unix)]
async fn run() -> Result<(), Box<dyn Error>> {
    let instance_root = parse_instance_root(std::env::args_os().skip(1))?;
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
fn parse_instance_root(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, io::Error> {
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--instance-root")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: pov-api --instance-root <path>",
        ));
    }
    let root = arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: pov-api --instance-root <path>",
        )
    })?;
    if arguments.next().is_some() || root.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: pov-api --instance-root <path>",
        ));
    }
    Ok(PathBuf::from(root))
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
    use super::parse_instance_root;

    #[test]
    fn production_instance_root_is_explicit_and_exact() {
        assert_eq!(
            parse_instance_root(
                ["--instance-root", "/tmp/pov-instance"]
                    .into_iter()
                    .map(Into::into)
            )
            .expect("explicit root"),
            std::path::PathBuf::from("/tmp/pov-instance")
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
            assert!(parse_instance_root(arguments.into_iter()).is_err());
        }
    }
}
