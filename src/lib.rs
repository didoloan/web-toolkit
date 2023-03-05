pub mod encrypt;
pub use encrypt::{hasher,jwt};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_test_num_aud() {
        jwt::generate_key_pair_if_absent().unwrap();
        let keys = jwt::get_keys_as_str().unwrap();
        let token = jwt::sign::<u64>(Some(25), keys.0.as_str(), 5).unwrap();
        assert_eq!(jwt::verify::<u64>(token.as_str(), keys.1.as_str()).unwrap(), 25u64);
    }

    #[test]
    fn hashandverify(){
        let pass = "testpassword";
        let hashed = hasher::hash(pass.to_string()).unwrap();
        assert_eq!(true, hasher::verify(pass, hashed.as_str()).unwrap());
    }
}
