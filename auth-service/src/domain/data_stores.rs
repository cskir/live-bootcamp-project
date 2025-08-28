use crate::domain::{Email, Password};

use super::User;
use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
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

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TwoFACode(Secret<String>);

impl TwoFACode {
    pub fn parse(code: Secret<String>) -> Result<Self> {
        let code_as_u32 = code
            .expose_secret()
            .parse::<u32>()
            .wrap_err("Invalid 2FA code")?;

        if (100_000..=999_999).contains(&code_as_u32) {
            Ok(Self(code))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Serialize for TwoFACode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        Self(Secret::new(rng.gen_range(100000..999999).to_string()))
    }
}

impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginAttemptId(Secret<String>);

impl LoginAttemptId {
    pub fn parse(id: Secret<String>) -> Result<Self> {
        let parse_id = Uuid::parse_str(id.expose_secret()).wrap_err("Invalid login attempt Id")?;
        Ok(Self(Secret::new(parse_id.to_string())))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(Secret::new(Uuid::new_v4().to_string()))
    }
}

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Serialize for LoginAttemptId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl AsRef<Secret<String>> for LoginAttemptId {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::TwoFACode;

    #[test]
    fn empty_code_is_rejected() {
        let code = Secret::new("".to_string());
        assert!(TwoFACode::parse(code).is_err());
    }

    #[test]
    fn short_code_is_rejected() {
        let code = Secret::new("12345".to_string());
        assert!(TwoFACode::parse(code).is_err());
    }

    #[test]
    fn long_code_is_rejected() {
        let code = Secret::new("1234567".to_string());
        assert!(TwoFACode::parse(code).is_err());
    }

    #[test]
    fn not_numeric_code_is_rejected() {
        let code = Secret::new("12345a".to_string());
        assert!(TwoFACode::parse(code).is_err());
    }

    use super::LoginAttemptId;

    #[test]
    fn empty_id_is_rejected() {
        let id = Secret::new("".to_string());
        assert!(LoginAttemptId::parse(id).is_err());
    }

    #[test]
    fn invalid_uuid_is_rejected() {
        let id = Secret::new("invalid-uuid".to_string());
        assert!(LoginAttemptId::parse(id).is_err());
    }

    #[test]
    fn valid_uuid_is_accepted() {
        let id = Secret::new(uuid::Uuid::new_v4().to_string());
        assert!(LoginAttemptId::parse(id).is_ok());
    }
}
