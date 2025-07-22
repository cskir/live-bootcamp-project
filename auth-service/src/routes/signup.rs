use axum::{http::StatusCode, response::IntoResponse};

// For now we will simply return a 200 (OK) status code.
pub async fn signup() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
