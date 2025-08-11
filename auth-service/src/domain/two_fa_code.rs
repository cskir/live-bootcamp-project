use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
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
}
