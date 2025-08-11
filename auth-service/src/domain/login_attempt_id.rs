use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
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
