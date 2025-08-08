use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    let verify_token_request = serde_json::json!({
        "token": auth_cookie.value()
    });

    let response = app.post_verify_token(&verify_token_request).await;
    assert_eq!(response.status().as_u16(), 200, "Expected 200 OK response");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let cookie_str = &format!(
        "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
        JWT_COOKIE_NAME
    );

    let verify_token_request = serde_json::json!({
        "token": cookie_str
    });

    let response = app.post_verify_token(&verify_token_request).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned(),
    )
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    let verify_token_request = serde_json::json!({
        "token": auth_cookie.value()
    });

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_token(&verify_token_request).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned(),
    )
}

#[tokio::test]
async fn should_return_422_if_malformed_request() {
    let app = TestApp::new().await;

    let verify_token_requests = [
        serde_json::json!({
            "tok": "token"
        }),
        serde_json::json!({}),
    ];

    for verify_token_request in verify_token_requests.iter() {
        let response = app.post_verify_token(verify_token_request).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Malformed request: {:?}",
            verify_token_request
        );
    }
}
