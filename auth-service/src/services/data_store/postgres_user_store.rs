use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;
use std::error::Error;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Some(_) = sqlx::query!(
            "SELECT email FROM users WHERE email = $1",
            user.email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        {
            return Err(UserStoreError::UserAlreadyExists);
        }

        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        match sqlx::query!(
            "INSERT INTO users VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() == 0 {
                    Err(UserStoreError::UserAlreadyExists)
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        {
            Some(row) => Ok(User::new(
                Email::parse(row.email).unwrap(),
                Password::parse(row.password_hash).unwrap(),
                row.requires_2fa,
            )),
            None => Err(UserStoreError::UserNotFound),
        }
    }
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        verify_password_hash(
            user.password.as_ref().to_string(),
            password.as_ref().to_string(),
        )
        .await
        .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}

async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error>> {
    tokio::task::spawn_blocking(move || {
        let expected_password_hash: PasswordHash<'_> =
            PasswordHash::new(expected_password_hash.as_ref())?;
        Argon2::default().verify_password(password_candidate.as_bytes(), &expected_password_hash)
    })
    .await??;

    Ok(())
}

async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error>> {
    let handle: Result<String, Box<dyn Error + Send + Sync>> =
        tokio::task::spawn_blocking(move || {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());

            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)
                    .map_err(|e| <argon2::Error as Into<Box<dyn Error + Send + Sync>>>::into(e))?,
            )
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                <argon2::password_hash::Error as Into<Box<dyn Error + Send + Sync>>>::into(e)
            })?
            .to_string();

            Ok(password_hash)
        })
        .await?;

    let password_hash = match handle {
        Ok(password_hash) => password_hash,
        Err(e) => return Err(e),
    };

    Ok(password_hash)
}
