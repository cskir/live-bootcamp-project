use crate::domain::{Email, Password};

use super::User;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug)]
pub enum BannedTokenStoreError {
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        if code.len() != 6 || !code.chars().all(char::is_numeric) {
            return Err(format!("Invalid TwoFACode: {}", code));
        }
        Ok(Self(code))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        Self(rng.gen_range(100000..999999).to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginAttemptId(pub String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        Uuid::parse_str(&id).map_err(|_| format!("Invalid LoginAttemptId: {}", id))?;
        Ok(Self(id))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::TwoFACode;

    #[test]
    fn empty_code_is_rejected() {
        let code = "".to_string();
        assert!(TwoFACode::parse(code).is_err());
    }

    #[test]
    fn short_code_is_rejected() {
        let code = "12345".to_string();
        assert!(TwoFACode::parse(code).is_err());
    }

    #[test]
    fn long_code_is_rejected() {
        let code = "1234567".to_string();
        assert!(TwoFACode::parse(code).is_err());
    }

    #[test]
    fn not_numeric_code_is_rejected() {
        let code = "12345a".to_string();
        assert!(TwoFACode::parse(code).is_err());
    }

    use super::LoginAttemptId;

    #[test]
    fn empty_id_is_rejected() {
        let id = "".to_string();
        assert!(LoginAttemptId::parse(id).is_err());
    }

    #[test]
    fn invalid_uuid_is_rejected() {
        let id = "invalid-uuid".to_string();
        assert!(LoginAttemptId::parse(id).is_err());
    }

    #[test]
    fn valid_uuid_is_accepted() {
        let id = uuid::Uuid::new_v4().to_string();
        assert!(LoginAttemptId::parse(id).is_ok());
    }
}
