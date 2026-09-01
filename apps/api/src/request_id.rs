use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Replaces untrusted inbound request IDs with a server-generated correlation ID.
pub async fn assign(mut request: Request<Body>, next: Next) -> Response {
    let header_name = HeaderName::from_static(REQUEST_ID_HEADER);
    let Ok(request_id) = HeaderValue::from_str(&Uuid::now_v7().to_string()) else {
        return next.run(request).await;
    };

    request
        .headers_mut()
        .insert(header_name.clone(), request_id.clone());
    let mut response = next.run(request).await;
    response.headers_mut().insert(header_name, request_id);
    response
}
