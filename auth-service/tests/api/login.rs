use crate::helpers::{get_random_email, ExtractResponse, TestApp};
use auth_service::{domain::Email, routes::TwoFactorAuthResponse, ErrorResponse};

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(random_email).unwrap();

    let result = app.two_fa_code_store.read().await.get_code(&email).await;

    assert!(result.is_ok(), "Failed to get 2FA code from store");

    let (login_attempt_id, _) = result.unwrap();

    assert_eq!(json_body.login_attempt_id, login_attempt_id.as_ref());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;
    let login_requests = [
        serde_json::json!({
            "email": "",
            "password": "password123"
        }),
        serde_json::json!({
            "email": "a@a.com",
            "password": ""
        }),
        serde_json::json!({
            "email": "",
            "password": ""
        }),
        serde_json::json!({
            "email": "aa.com",
            "password": "password123"
        }),
        serde_json::json!({
            "email": "a@a.com",
            "password": "passwor"
        }),
    ];

    for login_request in login_requests.iter() {
        let response = app.post_login(login_request).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Invalid input: {:?}",
            login_request
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    let test_user = serde_json::json!({
        "email": random_email.clone(),
        "password": "password123",
        "requires2FA": true
    });
    app.post_signup(&test_user).await;

    let test_cases = vec![
        (random_email.as_str(), "wrong_password"),
        ("wrong@email.com", "password123"),
        ("wrong@email.com", "wrong_password"),
    ];

    for (email, password) in test_cases {
        let login_request = serde_json::json!({
            "email": email,
            "password": password,
        });

        let response = app.post_login(&login_request).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: {:?}",
            login_request
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_request() {
    let mut app = TestApp::new().await;

    let login_requests = [
        serde_json::json!({
            "password": "password123"
        }),
        serde_json::json!({
            "email": "a@a.com",
        }),
        serde_json::json!({
            "e-mail": "a@a.com",
            "password": "password123"
        }),
        serde_json::json!({}),
    ];

    for login_request in login_requests.iter() {
        let response = app.post_login(login_request).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Malformed request: {:?}",
            login_request
        );
    }

    app.clean_up().await;
}
