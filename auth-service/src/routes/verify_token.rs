use std::sync::Arc;

use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;
use crate::domain::AuthAPIError;
use crate::utils::auth::validate_token;

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = request.token;

    let banned_token_store = Arc::clone(&state.banned_token_store);

    validate_token(&token, banned_token_store)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize, Serialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
