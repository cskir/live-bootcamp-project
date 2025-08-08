use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::app_state::AppState;
use crate::domain::AuthAPIError;
use crate::utils::auth::validate_token;
use crate::utils::constants::JWT_COOKIE_NAME;

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    let banned_token_store = Arc::clone(&state.banned_token_store);

    match validate_token(&token, banned_token_store).await {
        Ok(_) => {}
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }

    let jar = jar.remove(JWT_COOKIE_NAME);

    let mut banned_token_store = state.banned_token_store.write().await;

    banned_token_store.ban_token(token).await;

    (jar, Ok(StatusCode::OK))
}
