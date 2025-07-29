mod data_stores;
mod error;
mod user;

pub use data_stores::*;
pub use error::*;
pub use user::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if email.is_empty() || !email.contains('@') {
            Err("Invalid email format".to_string())
        } else {
            Ok(Email(email))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, String> {
        if password.len() < 8 {
            Err("Invalid password format".to_string())
        } else {
            Ok(Password(password))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use std::any::type_name_of_val;

    use super::*;

    #[test]
    fn test_email_parse_valid() {
        let email = Email::parse("".to_string());
        assert!(email.is_err());
        let email = Email::parse("a.com".to_string());
        assert!(email.is_err());

        let email = Email::parse("a@a.com".to_string()).unwrap();
        assert_eq!(email.0, "a@a.com");
        let email = Email::parse("a@acom".to_string()).unwrap();
        assert_eq!(email.0, "a@acom");
    }

    #[test]
    fn test_email_as_ref() {
        let email = Email::parse("a@a.com".to_string()).unwrap();
        assert_eq!(type_name_of_val(email.as_ref(),), "str");
    }

    #[test]
    fn test_password_parse_valid() {
        let password = Password::parse("".to_string());
        assert!(password.is_err());
        let password = Password::parse("1234567".to_string());
        assert!(password.is_err());

        let password = Password::parse("12345678".to_string()).unwrap();
        assert_eq!(password.0, "12345678");
    }

    #[test]
    fn test_password_as_ref() {
        let password = Password::parse("12345678".to_string()).unwrap();
        assert_eq!(type_name_of_val(password.as_ref(),), "str");
    }
}
