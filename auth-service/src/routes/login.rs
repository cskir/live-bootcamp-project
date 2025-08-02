use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;
use crate::domain::{AuthAPIError, Email, Password, User};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    user_store
        .validate_user(&email, &password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let user = user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok(StatusCode::OK.into_response())
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LoginResponse {
    pub message: String,
    pub login_attempt_id: String,
}
