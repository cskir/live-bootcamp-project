use crate::domain::BannedTokenStore;
use std::collections::HashSet;

#[derive(Default, Clone)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>,
}
#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn ban_token(&mut self, token: String) {
        self.banned_tokens.insert(token);
    }

    async fn is_banned(&self, token: &str) -> bool {
        self.banned_tokens.contains(token)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ban_token() {
        let mut store = HashsetBannedTokenStore {
            banned_tokens: HashSet::new(),
        };

        let token = "test_token".to_string();
        store.ban_token(token.clone()).await;

        assert!(store.banned_tokens.len() == 1);
        assert!(store.banned_tokens.contains(&token));
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut store = HashsetBannedTokenStore {
            banned_tokens: HashSet::new(),
        };

        let token = "test_token".to_string();
        store.ban_token(token.clone()).await;

        assert!(store.is_banned(&token).await);
        assert!(!store.is_banned("another_token").await);
    }
}
