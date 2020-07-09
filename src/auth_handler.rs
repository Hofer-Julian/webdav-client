use crate::error::Error;
use crate::error::Result;
use base64;
use base64::write::EncoderWriter as Base64Encoder;
use isahc::http::header;
use isahc::prelude::*;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use regex::Regex;
use std::io::Write;

#[derive(Clone, Debug)]
pub struct AuthHandler {
    pub domain: Option<String>,
    pub username: String,
    pub password: Option<String>,
    basic_challenge: Option<String>,
    digest_challenge: Option<String>,
}

impl AuthHandler {
    pub fn new<S>(domain: Option<S>, username: S, password: Option<S>) -> Self
    where
        S: Into<String>,
    {
        let domain = match domain {
            Some(d) => Some(d.into()),
            None => None,
        };

        let password = match password {
            Some(p) => Some(p.into()),
            None => None,
        };

        Self {
            domain,
            username: username.into(),
            password,
            basic_challenge: None,
            digest_challenge: None,
        }
    }

    pub fn authenticate_request<T>(
        &mut self,
        request: Request<T>,
        response: Option<Response<T>>,
    ) -> Result<Request<T>> {
        if let Some(ref domain) = self.domain {
            todo!();
        }

        if let Some(ref response) = response {
            // We are processing a 401 response
            let new_basic_challenge: Option<String> = None;
            let new_digest_challenge: Option<String> = None;
            lazy_static! {
                static ref STALE: Regex = Regex::new(r"(?i)stale=true").unwrap();
            }

            for header in response.headers().get_all(header::WWW_AUTHENTICATE) {
                if let Ok(header) = header.to_str() {
                    if header.starts_with("Basic") {
                        if self.basic_challenge.is_some() {
                            warn!("Basic credentials did not work last time -> aborting");
                            self.basic_challenge = None;
                            return Err(Error::Authenticate);
                        }
                    } else if header.starts_with("Digest") && !STALE.is_match(header) {
                        warn!("Digest credentials did not work last time and server nonce has not expired -> aborting");
                        self.digest_challenge = None;
                        return Err(Error::Authenticate);
                    }
                }
            }
            self.basic_challenge = new_basic_challenge;
            self.digest_challenge = new_digest_challenge;
        } else {
            // We are not processing a 401 response
            if self.basic_challenge.is_none() && self.digest_challenge.is_none() {
                info!("Trying Basic auth preemptively");
                self.basic_challenge = Some("Basic".to_string());
            }
        }

        if let Some(ref digest_challenge) = self.digest_challenge {
            info!("Adding Digest authorization request for {}", request.uri());
            return self.digest_auth(request, &digest_challenge);
        } else if self.basic_challenge.is_some() {
            info!("Adding Basic authorization request for {}", request.uri());
            return self.basic_auth(request);
        } else if response.is_some() {
            warn!("No supported authentication scheme");
        }

        return Err(Error::Authenticate);
    }

    pub fn digest_auth<T>(
        &self,
        request: Request<T>,
        digest_challenge: &String,
    ) -> Result<Request<T>> {
        lazy_static! {
            static ref REALM: Regex = Regex::new(r#"(?i)realm="([[:ascii:]]+)""#).unwrap();
            static ref OPAQUE: Regex = Regex::new(r#"(?i)opaque="([[:xdigit:]]+)""#).unwrap();
            static ref NONCE: Regex = Regex::new(r#"(?i)nonce="([[:xdigit:]]+)""#).unwrap();
            static ref ALGORITHM: Regex = Regex::new(r#"(?i)algorithm="([[:ascii:]]+)""#).unwrap();
            static ref QOP: Regex = Regex::new(r#"(?i)qop="([[:ascii:]]+)""#).unwrap();
        }
        let mut params = Vec::new();

        let realm = match REALM
            .captures(digest_challenge)
            .and_then(|capture| capture.get(1))
        {
            Some(r) => {
                let realm = r.as_str();
                params.push(format!("realm={}", Self::quoted_string(realm.to_owned())));
                realm
            }
            None => {
                warn! {"No realm provided, aborting Digest auth"};
                return Err(Error::Authenticate);
            }
        };

        let nonce = match NONCE
            .captures(digest_challenge)
            .and_then(|capture| capture.get(1))
        {
            Some(n) => {
                let nonce = n.as_str();
                params.push(format!("nonce={}", Self::quoted_string(nonce.to_owned())));
                nonce
            }
            None => {
                warn! {"No nonce provided, aborting Digest auth"};
                return Err(Error::Authenticate);
            }
        };

        if let Some(o) = OPAQUE
            .captures(digest_challenge)
            .and_then(|capture| capture.get(1))
        {
            let opaque = o.as_str();
            params.push(format!("opaque={}", Self::quoted_string(opaque.to_owned())));
        }

        if let Some(a) = ALGORITHM
            .captures(digest_challenge)
            .and_then(|capture| capture.get(1))
        {
            let algorithm = a.as_str();
            params.push(format!(
                "algorithm={}",
                Self::quoted_string(algorithm.to_owned())
            ));
        }

        let method = request.method();
        let digest_uri = request.uri().path().to_owned();
        params.push(format!("uri={}", Self::quoted_string(digest_uri)));

        let response = match QOP
            .captures(digest_challenge)
            .and_then(|capture| capture.get(1))
        {
            Some(q) => {
                let qop = q.as_str();
                todo!("Determine qop (it is different and it is also not quoted");
            }
            None => {
                debug!("Using legacy Digest auth");
                // legacy (backwards compatibility with RFC 2069)
                todo!();
            }
        };

        todo!();
    }

    fn quoted_string(s: String) -> String {
        format!(r#""{}""#, s.replace("\"", "\\\""))
    }

    pub fn basic_auth<T>(&self, mut request: Request<T>) -> Result<Request<T>> {
        let mut header_value = b"Basic ".to_vec();
        {
            let mut encoder = Base64Encoder::new(&mut header_value, base64::STANDARD);
            // The unwraps here are fine because Vec::write* is infallible.
            write!(encoder, "{}:", self.username).unwrap();
            if let Some(ref password) = self.password {
                write!(encoder, "{}", password).unwrap();
            }
        }

        request.headers_mut().insert(
            header::AUTHORIZATION,
            isahc::http::HeaderValue::from_bytes(&header_value)?,
        );
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ascii() {
        let original = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();

        let response = Response::new(());
        let auth_handler = AuthHandler::new(None, "user", Some("password"));
        let request = auth_handler.basic_auth(original).unwrap();

        assert_eq!(
            request.headers().get(header::AUTHORIZATION).unwrap(),
            "Basic dXNlcjpwYXNzd29yZA=="
        );
    }

    #[test]
    fn test_basic_utf8() {
        let original = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();

        let response = Response::new(());
        // Test special characters
        let auth_handler = AuthHandler::new(None, "username", Some("paßword"));
        let request = auth_handler.basic_auth(original).unwrap();
        assert_eq!(
            request.headers().get(header::AUTHORIZATION).unwrap(),
            "Basic dXNlcm5hbWU6cGHDn3dvcmQ="
        );
    }
}
