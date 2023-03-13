pub mod hasher {
    use std::io::{Error, ErrorKind};
    use argon2::{
        password_hash::{
            rand_core::OsRng,
            PasswordHash, PasswordHasher, PasswordVerifier, SaltString
        },
        Argon2
    };

    pub fn hash(passwd:&str) -> Result<String, Error> {
        let salt:SaltString = SaltString::generate(&mut OsRng);
        let argon:Argon2 = Argon2::default();
        match argon.hash_password(passwd.as_bytes(), &salt) {
            Ok(pass) => Ok(pass.to_string()),
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()))
        }
    }

    pub fn verify(plain:&str, hashed: &str) -> Result<bool, std::io::Error> {
        let argon:Argon2 = Argon2::default();
        match PasswordHash::new(hashed) {
            Ok(ph) => {
                Ok(argon.verify_password(plain.as_bytes(), &ph).is_ok())
            },
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()))
        }
    }
    
}

pub mod jwt {

    const PRIVATE:&str = "private_key.pem";
    const PUBLIC:&str = "public_key.pem";
    
    use std::{result::Result::Ok, str::FromStr, fmt::Display, collections::HashSet};
    use openssl::pkey::{PKey, Private};
    use std::{io::{Error, ErrorKind}, fs, path::Path};
    use jwt_simple::{prelude::{Ed25519KeyPair,Claims, VerificationOptions, Ed25519PublicKey, NoCustomClaims, EdDSAPublicKeyLike, Duration, EdDSAKeyPairLike, JWTClaims}};

    pub struct SignOptions<'a, T:ToString> {
        pub issuer: Option<&'a str>,
        pub expiry: Option<Duration>,
        pub audience: Option<T>
    }

    #[derive(Default)]
    pub struct VerifyOptions {
        pub valid_audiences: Option<HashSet<String>>,
        pub valid_issuers: Option<HashSet<String>>,
        pub valid_after_expiry: Option<Duration>
    }

    impl<'a, T:ToString+Copy> SignOptions<'a, T> {
        fn get_claim(&self) -> JWTClaims<NoCustomClaims> {
            let mut claim = Claims::create(match self.expiry {
                Some(exp) => exp,
                None => std::time::Duration::MAX.into()
            });

            claim = match self.audience {
                Some(audience) => claim.with_audience(audience),
                None => claim,
            };

            match self.issuer {
                Some(iss) => claim.with_issuer(iss),
                None => claim
            }
        }
    }

    pub fn generate_key_pair_if_absent() -> Result<(), Error> {

        let priv_key:PKey<Private> = match fs::read(PRIVATE) {
            Ok(key_in_bytes) => match PKey::private_key_from_pem(key_in_bytes.as_slice()){
                Ok(k) => k,
                Err(_) => match PKey::generate_ed25519() {
                    Ok(vv) => vv,
                    Err(e) => {
                        return Err(Error::new(ErrorKind::Other, e.to_string()));    
                    }
                },
            },
            Err(_) => match PKey::generate_ed25519() {
                Ok(val) => val,
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, e.to_string()));    
                }
            }
        };

        match priv_key.private_key_to_pem_pkcs8() {
            Ok(str) => {
                match fs::write(PRIVATE, str) {
                    Ok(_) => {},
                    Err(e) => {
                        return Err(Error::new(ErrorKind::Other, e.to_string()));    
                    }
                }
            },
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));    
            }
        };

        match priv_key.public_key_to_pem() {
            Ok(str) => {
                match fs::write(PUBLIC, str) {
                    Ok(_) => {},
                    Err(e) => {
                        return Err(Error::new(ErrorKind::Other, e.to_string()));    
                    }
                }
            },
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));    
            }
        };

        Ok(())

    }


    pub fn get_keys_as_str() -> Result<(String,String), Error> {
        let pub_bytes = match fs::read(Path::new("public_key.pem")) {
            Ok(bts) => bts,
            Err(e) => {return Err(Error::new(ErrorKind::Other, e.to_string()));}
        };

        let priv_bytes = match fs::read(Path::new("private_key.pem")) {
            Ok(bts) => bts,
            Err(e) => {return Err(Error::new(ErrorKind::Other, e.to_string()));}
        };

        Ok((String::from_utf8(priv_bytes).unwrap(),String::from_utf8(pub_bytes).unwrap()))
    }

    pub fn sign<T:ToString+Copy>(pem_str:&str, options:SignOptions<T>) -> Result<String, Error> {
        let key_pair = match Ed25519KeyPair::from_pem(pem_str) {
            Ok(pair) => pair,
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()))
            }
        };

        let claim = options.get_claim();

        match key_pair.sign(claim) {
            Ok(token) => Ok(token),
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()))
        }
    }

    pub fn verify<T>(token:&str, pub_pem_str:&str, options:VerifyOptions) -> Result<T, Error>
    where 
    <T as FromStr>::Err:Display,
    T:FromStr
    {
        let opts:VerificationOptions = VerificationOptions { accept_future:false, time_tolerance: options.valid_after_expiry, allowed_issuers: options.valid_issuers, allowed_audiences: options.valid_audiences, ..Default::default() };
        let pub_key = match Ed25519PublicKey::from_pem(pub_pem_str) {
            Ok(key) => key,
            Err(e) => {return Err(Error::new(ErrorKind::Other, e.to_string()))}
        };
        match pub_key.verify_token::<NoCustomClaims>(token, Some(opts)) {
            Ok(clm) => {
                let aud = match clm.audiences {
                    Some(adienc) => adienc,
                    None => {return Err(Error::new(ErrorKind::Other, "Empty audience"))}
                };
                match aud.into_string() {
                    Ok(au_clm) => match T::from_str(&au_clm) {
                        Ok(id) => Ok(id),
                        Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()))
                    },
                    Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()))
                }
            },
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()))
        }
    }
}