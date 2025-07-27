use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) if user.password == password => Ok(()),
            Some(_) => Err(UserStoreError::InvalidCredentials),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("user1", "password123", true);
        let result = store.add_user(user);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ());
        assert_eq!(store.users.len(), 1);

        let user = User::new("user1", "password123", true);
        let result = store.add_user(user);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("user1", "password123", true);
        let user_clone = user.clone();
        store.add_user(user).unwrap();

        let retr_user_ok = store.get_user("user1");
        assert!(retr_user_ok.is_ok());
        assert_eq!(retr_user_ok.unwrap(), user_clone);

        let retr_user_not_found = store.get_user("user2");
        assert!(retr_user_not_found.is_err());
        assert_eq!(
            retr_user_not_found.unwrap_err(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("user1", "password123", true);
        store.add_user(user).unwrap();

        let result_ok = store.validate_user("user1", "password123");
        assert!(result_ok.is_ok());
        assert_eq!(result_ok.unwrap(), ());

        let result_invalid_cred = store.validate_user("user1", "password234");
        assert!(result_invalid_cred.is_err());
        assert_eq!(
            result_invalid_cred.unwrap_err(),
            UserStoreError::InvalidCredentials
        );

        let result_not_found = store.validate_user("user2", "password234");
        assert!(result_not_found.is_err());
        assert_eq!(result_not_found.unwrap_err(), UserStoreError::UserNotFound);
    }
}
