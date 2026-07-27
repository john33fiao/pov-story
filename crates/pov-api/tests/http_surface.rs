use std::net::{IpAddr, Ipv4Addr};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use pov_api::{DEFAULT_BIND_ADDRESS, app};
use tower::ServiceExt;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

async fn response_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("response body should fit within the test limit");

    String::from_utf8(bytes.to_vec()).expect("response body should be UTF-8")
}

#[test]
fn default_bind_address_is_loopback_only() {
    assert_eq!(DEFAULT_BIND_ADDRESS.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(DEFAULT_BIND_ADDRESS.port(), 8080);
}

#[tokio::test]
async fn health_is_data_independent_json() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("health request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static(
            "application/json; charset=utf-8"
        ))
    );
    assert_eq!(response_text(response).await, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn root_serves_the_frontend_shell_with_local_only_policy() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("shell request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("text/html"))
    );
    assert_eq!(
        response.headers().get(header::CONTENT_SECURITY_POLICY),
        Some(&header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; \
             connect-src 'self'; img-src 'self' data:; font-src 'self'; \
             object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        ))
    );

    let body = response_text(response).await;
    assert!(body.contains(r#"<div id="root"></div>"#));
    assert!(!body.contains("https://"));
    assert!(!body.contains("http://"));
}

#[tokio::test]
async fn unknown_api_path_does_not_fall_back_to_the_spa() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/missing")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("missing API request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        !response_text(response)
            .await
            .contains(r#"<div id="root"></div>"#)
    );
}

#[tokio::test]
async fn non_get_request_cannot_serve_the_spa() {
    let response = app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("non-GET request should complete");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers().get(header::ALLOW),
        Some(&header::HeaderValue::from_static("GET, HEAD"))
    );
    assert!(
        !response_text(response)
            .await
            .contains(r#"<div id="root"></div>"#)
    );
}

#[tokio::test]
async fn head_request_preserves_shell_headers_without_a_body() {
    let get_response = app()
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("GET request should complete");
    let get_content_length = get_response
        .headers()
        .get(header::CONTENT_LENGTH)
        .cloned()
        .expect("GET response should declare its representation length");

    let response = app()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("HEAD request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("text/html"))
    );
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&get_content_length)
    );
    assert!(response_text(response).await.is_empty());
}

#[tokio::test]
async fn missing_or_traversal_asset_is_not_served() {
    for uri in [
        "/assets/missing.js",
        "/%2e%2e/Cargo.toml",
        "/%2e%2e/extensionless-secret",
    ] {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request should be valid"),
            )
            .await
            .expect("asset request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn emitted_javascript_is_served_with_safe_headers() {
    let shell_response = app()
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("shell request should complete");
    let shell = response_text(shell_response).await;
    let script_path = attribute_value(&shell, r#"src=""#);

    let asset_response = app()
        .oneshot(
            Request::builder()
                .uri(script_path)
                .body(Body::empty())
                .expect("asset request should be valid"),
        )
        .await
        .expect("asset request should complete");

    assert_eq!(asset_response.status(), StatusCode::OK);
    assert_eq!(
        asset_response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("text/javascript"))
    );
    assert_eq!(
        asset_response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        asset_response.headers().get("x-content-type-options"),
        Some(&header::HeaderValue::from_static("nosniff"))
    );
}

fn attribute_value<'a>(document: &'a str, prefix: &str) -> &'a str {
    let start = document
        .find(prefix)
        .expect("document should contain the attribute")
        + prefix.len();
    let remainder = &document[start..];
    let end = remainder
        .find('"')
        .expect("attribute value should end with a quote");

    &remainder[..end]
}
