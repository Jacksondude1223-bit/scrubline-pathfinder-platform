use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use pathfinder::{api::Api, runtime, store::Store};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
async fn home() -> Json<Value> {
    Json(
        json!({"service":"scrubline-control-plane-test","health":"/health","storage":"ephemeral-memory","scope":"control-plane-only"}),
    )
}
async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("Cache-Control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("X-Scrubline-Test-Mode", "ephemeral-memory".parse().unwrap());
    response
}
fn router() -> Result<Router, vercel_runtime::Error> {
    let token = runtime::required_env("SCRUBLINE_API_TOKEN").map_err(std::io::Error::other)?;
    let enroll = runtime::required_env("SCRUBLINE_ENROLL_TOKEN").map_err(std::io::Error::other)?;
    configured_router(token, enroll)
}
fn configured_router(token: String, enroll: String) -> Result<Router, vercel_runtime::Error> {
    if token.is_empty() || enroll.is_empty() {
        return Err(std::io::Error::other("credentials are required").into());
    }
    if token == enroll {
        return Err(std::io::Error::other(
            "SCRUBLINE_API_TOKEN and SCRUBLINE_ENROLL_TOKEN must differ",
        )
        .into());
    }
    let state = Arc::new(Mutex::new(Api::new(
        Store::open("").map_err(std::io::Error::other)?,
        token,
        enroll,
        "primary".into(),
    )));
    Ok(Api::router(state)
        .route("/", get(home))
        .layer(middleware::from_fn(headers)))
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), vercel_runtime::Error> {
    let app = tower::ServiceBuilder::new()
        .layer(vercel_runtime::axum::VercelLayer::new())
        .service(router()?);
    vercel_runtime::run(app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[test]
    fn rejects_missing_or_shared_credentials() {
        for (operator, enroll) in [("", "enroll"), ("operator", ""), ("same", "same")] {
            assert!(configured_router(operator.into(), enroll.into()).is_err());
        }
    }
    #[tokio::test]
    async fn test_metadata_and_control_routes_keep_ephemeral_headers() {
        let router = configured_router("operator".into(), "enroll".into()).unwrap();
        for (path, status) in [("/", 200), ("/health", 200), ("/v1/nodes", 401)] {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()["Cache-Control"], "no-store");
            assert_eq!(
                response.headers()["X-Scrubline-Test-Mode"],
                "ephemeral-memory"
            );
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            if path == "/" {
                assert_eq!(value["storage"], "ephemeral-memory");
            }
        }
    }
}
