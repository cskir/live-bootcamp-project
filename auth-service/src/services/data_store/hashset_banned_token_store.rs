use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};
use std::collections::HashSet;

#[derive(Default, Clone)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}
#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashsetBannedTokenStore::default();

        let token = Secret::new("test_token".to_string());
        let result = store.add_token(token.clone()).await;

        assert!(result.is_ok());
        assert!(store.tokens.len() == 1);
        assert!(store.tokens.contains(token.expose_secret()));
    }

    #[tokio::test]
    async fn test_contains_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = Secret::new("test_token".to_string());
        store.add_token(token.clone()).await.unwrap();

        assert!(store.contains_token(&token).await.unwrap());
        assert!(!store
            .contains_token(&Secret::new("other_token".to_string()))
            .await
            .unwrap());
    }
}
