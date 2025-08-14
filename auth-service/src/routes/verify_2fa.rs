use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(login_attempt_id) => login_attempt_id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Ok(two_fa_code) => two_fa_code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    {
        let two_fa_code_store = state.two_fa_code_store.read().await;

        let (stored_login_attempt_id, stored_two_fa_code) =
            match two_fa_code_store.get_code(&email).await {
                Ok(code) => code,
                Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
            };

        if stored_login_attempt_id != login_attempt_id || stored_two_fa_code != two_fa_code {
            return (jar, Err(AuthAPIError::IncorrectCredentials));
        }
    }

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);

    {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;

        match two_fa_code_store.remove_code(&email).await {
            Ok(_) => {}
            Err(_) => return (updated_jar, Err(AuthAPIError::IncorrectCredentials)),
        };
    }

    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize, Serialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}
