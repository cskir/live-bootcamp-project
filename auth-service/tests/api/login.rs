use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_request() {
    let app = TestApp::new().await;

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
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
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
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let test_user = serde_json::json!({
        "email": random_email.clone(),
        "password": "password123",
        "requires2FA": true
    });
    app.post_signup(&test_user).await;

    let login_request = serde_json::json!({
        "email": random_email.clone(),
        "password": "password1234",
    });
    let response = app.post_login(&login_request).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Incorrect credentials: {:?}",
        login_request
    );
}
