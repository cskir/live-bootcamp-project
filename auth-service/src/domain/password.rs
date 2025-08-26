use color_eyre::eyre::{eyre, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self> {
        if password.len() < 8 {
            Err(eyre!("Invalid password format"))
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
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use std::any::type_name_of_val;

    #[test]
    fn empty_string_is_rejected() {
        let password = Password::parse("".to_string());
        assert!(password.is_err());
    }

    #[test]
    fn less_then_8_len_is_rejected() {
        let password = Password::parse("1234567".to_string());
        assert!(password.is_err());
    }

    #[test]
    fn test_password_as_ref() {
        let password = Password::parse("12345678".to_string()).unwrap();
        assert_eq!(type_name_of_val(password.as_ref(),), "str");
    }

    #[derive(Clone, Debug)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let password = FakePassword(8..38).fake_with_rng(g);
            Self(password)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).is_ok()
    }
}
