use std::error::Error;

use pov_api::{DEFAULT_BIND_ADDRESS, app};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(DEFAULT_BIND_ADDRESS).await?;
    axum::serve(listener, app()).await?;
    Ok(())
}
