#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub email: String,
    pub password: String,
    requires_2fa: bool,
}

impl User {
    pub fn new(email: &str, password: &str, requires_2fa: bool) -> Self {
        User {
            email: email.to_string(),
            password: password.to_string(),
            requires_2fa,
        }
    }

    // Additional methods for User can be added here
}
