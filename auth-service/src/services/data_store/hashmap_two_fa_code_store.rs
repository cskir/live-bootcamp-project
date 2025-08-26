use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};
use color_eyre::eyre::{eyre, Result};
use std::collections::HashMap;

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        if self.codes.remove(email).is_none() {
            return Err(TwoFACodeStoreError::UnexpectedError(eyre!(
                "code not found"
            )));
        }
        Ok(())
    }
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some((login_attempt_id, code)) => Ok((login_attempt_id.clone(), code.clone())),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Email, LoginAttemptId, TwoFACode};

    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("user1@a.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;

        assert!(result.is_ok());

        assert_eq!(store.codes.len(), 1);

        assert!(store.codes.contains_key(&email));

        let (stored_login_attempt_id, stored_code) =
            store.codes.get(&email).expect("Code not found in store");

        assert_eq!(stored_login_attempt_id, &login_attempt_id);

        assert_eq!(stored_code, &code);
    }

    #[tokio::test]
    async fn test_get_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("user1@a.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;

        assert!(result.is_ok());

        assert_eq!(store.codes.len(), 1);

        assert!(store.codes.contains_key(&email));

        let (stored_login_attempt_id, stored_code) = store
            .get_code(&email)
            .await
            .expect("Code not found in store");

        assert_eq!(stored_login_attempt_id, login_attempt_id);

        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn test_get_code_not_found() {
        let store = HashmapTwoFACodeStore::default();
        let email = Email::parse("user1@a.com".to_string()).unwrap();

        let result = store.get_code(&email).await;

        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("user1@a.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;

        assert!(result.is_ok());

        let result = store.remove_code(&email).await;

        assert!(result.is_ok());

        assert_eq!(store.codes.len(), 0);
    }

    #[tokio::test]
    async fn test_remove_code_not_found() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("user1@a.com".to_string()).unwrap();

        let result = store.remove_code(&email).await;

        assert!(result.is_err());
    }
}
