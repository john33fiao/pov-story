//! POV Story local HTTP surface.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use axum::{
    Router,
    body::Body,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::Embed;

pub const DEFAULT_BIND_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));

const CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'self'; script-src 'self'; style-src 'self'; ",
    "connect-src 'self'; img-src 'self' data:; font-src 'self'; ",
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
);

#[derive(Embed)]
#[folder = "../../web/dist/"]
struct WebAssets;

pub fn app() -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .fallback(api_not_found);

    Router::new().nest("/api", api).fallback(serve_web_asset)
}

async fn health() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"status":"ok"}"#,
    )
}

async fn api_not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn serve_web_asset(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .body(Body::empty())
            .expect("method response headers are valid");
    }

    let requested_path = uri.path().trim_start_matches('/');

    let response = if requested_path.is_empty() {
        embedded_asset_response("index.html")
    } else if !is_safe_asset_path(requested_path) {
        StatusCode::NOT_FOUND.into_response()
    } else if WebAssets::get(requested_path).is_some() {
        embedded_asset_response(requested_path)
    } else if !requested_path.contains('.') {
        embedded_asset_response("index.html")
    } else {
        StatusCode::NOT_FOUND.into_response()
    };

    if method == Method::HEAD {
        let (parts, _) = response.into_parts();
        Response::from_parts(parts, Body::empty())
    } else {
        response
    }
}

fn is_safe_asset_path(path: &str) -> bool {
    !path.contains(['%', '\\'])
        && path
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

fn embedded_asset_response(path: &str) -> Response {
    let Some(asset) = WebAssets::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let content_type = mime_guess::from_path(path).first_or_octet_stream();
    let data = asset.data.into_owned();
    let content_length = data.len().to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type.as_ref())
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY)
        .header("x-content-type-options", "nosniff")
        .body(Body::from(data))
        .expect("static response headers are valid")
}
