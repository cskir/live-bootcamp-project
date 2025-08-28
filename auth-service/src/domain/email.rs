use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use std::hash::Hash;
use validator::validate_email;

#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Self> {
        if validate_email(s.expose_secret()) {
            Ok(Self(s))
        } else {
            Err(eyre!("{} is not a valid email.", s.expose_secret()))
        }
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for Email {}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    use fake::{faker::internet::en::SafeEmail, Fake};
    use secrecy::Secret;
    use std::any::type_name_of_val;

    #[test]
    fn empty_string_is_rejected() {
        let email = Secret::new("".to_string());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_at_symbol_is_rejected() {
        let email = Secret::new("asd.com".to_string());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_username_is_rejected() {
        let email = Secret::new("@asd.com".to_string());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn missing_domain_is_rejected() {
        let email = Secret::new("asd@asd.".to_string());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn test_email_as_ref() {
        let email = Email::parse(Secret::new("a@a.com".to_string())).unwrap();
        assert_eq!(
            type_name_of_val(email.as_ref(),),
            "secrecy::Secret<alloc::string::String>"
        );
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
        Email::parse(Secret::new(valid_email.0)).is_ok()
    }
}
