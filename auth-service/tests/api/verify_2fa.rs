use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode},
    ErrorResponse,
};

use crate::helpers::{get_random_email, ExtractResponse, TestApp};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
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

    let email = Email::parse(random_email.clone()).unwrap();
    let result = app.two_fa_code_store.read().await.get_code(&email).await;
    assert!(result.is_ok(), "Failed to get 2FA code from store");

    let (stored_firts_login_attempt_id, stored_first_two_fa_code) = result.unwrap();

    let first_login_verify_2fa_request = serde_json::json!({
        "email": random_email,
        "loginAttemptId": stored_firts_login_attempt_id.as_ref(),
        "2FACode": stored_first_two_fa_code.as_ref(),
    });

    let response = app.post_verify_2fa(&first_login_verify_2fa_request).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response.get_auth_cookie().expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let input_requests = [
        ("", "", ""),
        ("", "loginAttemptId", "2FACode"),
        ("email", "", "2FACode"),
        ("email", "loginAttemptId", ""),
        ("email", "loginAttemptId", "2FACode"),
    ];

    for (email, login_attempt_id, two_fa_code) in input_requests.iter() {
        let input_request = serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": two_fa_code,
        });

        let response = app.post_verify_2fa(&input_request).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Invalid input: {:?}",
            input_request
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
}

#[tokio::test]
async fn should_return_401_if_invalid_credentials() {
    let app = TestApp::new().await;
    let email = get_random_email();
    let password = "password123".to_string();
    let test_user = serde_json::json!({
        "email": email.clone(),
        "password": password.clone(),
        "requires2FA": true
    });

    let response = app.post_signup(&test_user).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_request = serde_json::json!({
        "email": email.clone(),
        "password": password.clone(),
    });
    let response = app.post_login(&login_request).await;
    assert_eq!(response.status().as_u16(), 206);

    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    let emails = [email.clone(), get_random_email()];

    for email in emails.iter() {
        let verify_2fa_request = serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id.as_ref(),
            "2FACode": two_fa_code.as_ref(),
        });

        let response = app.post_verify_2fa(&verify_2fa_request).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: {:?}",
            verify_2fa_request
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
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;
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

    let email = Email::parse(random_email.clone()).unwrap();

    let result = app.two_fa_code_store.read().await.get_code(&email).await;

    assert!(result.is_ok(), "Failed to get 2FA code from store");

    let (stored_firts_login_attempt_id, stored_first_two_fa_code) = result.unwrap();

    let first_login_verify_2fa_request = serde_json::json!({
        "email": random_email,
        "loginAttemptId": stored_firts_login_attempt_id.as_ref(),
        "2FACode": stored_first_two_fa_code.as_ref(),
    });

    let response = app.post_verify_2fa(&first_login_verify_2fa_request).await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let response = app.post_verify_2fa(&first_login_verify_2fa_request).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        first_login_verify_2fa_request
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

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
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

    let email = Email::parse(random_email.clone()).unwrap();
    let result = app.two_fa_code_store.read().await.get_code(&email).await;
    assert!(result.is_ok(), "Failed to get 2FA code from store");

    let (stored_firts_login_attempt_id, stored_first_two_fa_code) = result.unwrap();

    let first_login_verify_2fa_request = serde_json::json!({
        "email": random_email,
        "loginAttemptId": stored_firts_login_attempt_id.as_ref(),
        "2FACode": stored_first_two_fa_code.as_ref(),
    });

    let response = app.post_verify_2fa(&first_login_verify_2fa_request).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response.get_auth_cookie().expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response = app.post_verify_2fa(&first_login_verify_2fa_request).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        first_login_verify_2fa_request
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

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = "test_code".to_string();

    let login_requests = [
        serde_json::json!({
            "loginAttemptId": login_attempt_id.clone().as_ref(),
        }),
        serde_json::json!({
            "email": random_email.clone(),
        }),
        serde_json::json!({
            "2FACode": two_fa_code.clone(),
        }),
        serde_json::json!({
            "email": random_email.clone(),
            "loginAttemptId": login_attempt_id.clone().as_ref(),
        }),
        serde_json::json!({
            "email": random_email.clone(),
            "2FACode": two_fa_code.clone(),
        }),
        serde_json::json!({
             "loginAttemptId": login_attempt_id.clone().as_ref(),
            "2FACode": two_fa_code.clone(),
        }),
        serde_json::json!({}),
    ];

    for login_request in login_requests.iter() {
        let response = app.post_verify_2fa(login_request).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Malformed request: {:?}",
            login_request
        );
    }
}
