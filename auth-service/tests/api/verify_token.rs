use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};

use crate::helpers::{get_random_email, ExtractResponse, TestApp};

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

    let auth_cookie = response.get_auth_cookie().expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    let verify_token_request = serde_json::json!({
        "token": token
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

    let test_cases = [
        serde_json::json!({"token": cookie_str}),
        serde_json::json!({"token": "invalid_token"}),
        serde_json::json!({"token": ""}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;

        assert_eq!(response.status().as_u16(), 401);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid auth token".to_owned(),
        )
    }
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

    let auth_cookie = response.get_auth_cookie().expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let verify_token_request = serde_json::json!({
        "token": token
    });

    let response = app.post_verify_token(&verify_token_request).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid auth token".to_owned(),
    )
}

#[tokio::test]
async fn should_return_422_if_malformed_request() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "tok": "token"
        }),
        serde_json::json!({}),
        serde_json::json!({"token": 0}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Malformed request: {:?}",
            test_case
        );
    }
}
