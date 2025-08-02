use validator::validate_email;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(s: String) -> Result<Email, String> {
        if validate_email(&s) {
            Ok(Self(s))
        } else {
            Err(format!("{} is not a valid email.", s))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    use fake::{faker::internet::en::SafeEmail, Fake};
    use std::any::type_name_of_val;

    #[test]
    fn empty_string_is_rejected() {
        let email = "".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_at_symbol_is_rejected() {
        let email = "asd.com".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_username_is_rejected() {
        let email = "@asd.com".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_domain_is_rejected() {
        let email = "asd@asd.".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn test_email_as_ref() {
        let email = Email::parse("a@a.com".to_string()).unwrap();
        assert_eq!(type_name_of_val(email.as_ref(),), "str");
    }

    #[derive(Clone, Debug)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let email = SafeEmail().fake_with_rng(g);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(valid_email.0).is_ok()
    }
}
