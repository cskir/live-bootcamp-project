use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let test_user = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&test_user).await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let invalid_users = [
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "a@a.com",
            "password": "",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "",
            "password": "",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email.replace("@", ""),
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "pwd1234",
            "requires2FA": true
        }),
    ];

    for invalid_user in invalid_users.iter() {
        let response = app.post_signup(invalid_user).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            invalid_user
        );
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to UserBody")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let test_user = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    app.post_signup(&test_user).await;
    let response = app.post_signup(&test_user).await;

    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned(),
    );
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
        }),
        serde_json::json!({
            "e-mail": random_email,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "true"
        }),
        serde_json::json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}
