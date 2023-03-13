pub mod encrypt;
pub use encrypt::{hasher,jwt};

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use jwt_simple::prelude::Duration;

    use crate::jwt::{SignOptions, VerifyOptions};

    use super::*;

    #[test]
    fn jwt_test_num_aud() {
        jwt::generate_key_pair_if_absent().unwrap();
        let keys = jwt::get_keys_as_str().unwrap();
        let token = jwt::sign::<u64>(keys.0.as_str(), SignOptions {
            expiry: Some(Duration::from_secs(5)),
            issuer: Some("cbd.ab"),
            audience: Some(25u64)
        }).unwrap();
        let mut hs = HashSet::new();
        hs.insert(String::from("abc.com"));
        hs.insert(String::from("cbd.ab"));
        let mut auds = HashSet::new();
        auds.insert(String::from("2"));
        auds.insert(String::from("35"));
        let aud = jwt::verify::<u64>(token.as_str(), keys.1.as_str(), VerifyOptions{valid_after_expiry:Some(Duration::from_secs(2)), valid_audiences:Some(auds), valid_issuers: Some(hs)});
        match aud {
            Ok(audience) => {
                assert_eq!(audience, 25u64);
            },
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }

    #[test]
    fn hashandverify() {
        let pass = "testpassword";
        let hashed = hasher::hash(pass).unwrap();
        let verified = hasher::verify(pass, hashed.as_str()).unwrap();
        assert_eq!(true, verified);
    }
}
