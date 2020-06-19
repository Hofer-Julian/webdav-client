use crate::error::Error;
use crate::error::Result;
use base64;
use base64::write::EncoderWriter as Base64Encoder;
use isahc::http::header;
use isahc::prelude::*;
use log::{info, warn};
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
        mut request: Request<T>,
        response: Option<Response<T>>,
    ) -> Result<Request<T>> {
        if let Some(ref domain) = self.domain {
            todo!();
        }

        if let Some(ref response) = response {
            // We are processing a 401 response
            let new_basic_challenge: Option<String> = None;
            let new_digest_challenge: Option<String> = None;

            todo!();

            self.basic_challenge = new_basic_challenge;
            self.digest_challenge = new_digest_challenge;
        } else {
            // We are not processing a 401 response
            if self.basic_challenge.is_none() && self.digest_challenge.is_none() {
                info!("Trying Basic auth preemptively");
                self.basic_challenge = Some("Basic".to_string());
            }
            todo!();
        }

        if self.digest_challenge.is_some() {
            info!("Adding Digest authorization request for {}", request.uri());
            return self.digest_auth(request, self.digest_challenge);
        } else if self.basic_challenge.is_some() {
            info!("Adding Basic authorization request for {}", request.uri());
            return self.basic_auth(request);
        } else if response.is_some() {
            warn!("No supported authentication scheme");
        }

        return Err(Error::General);
    }

    pub fn digest_auth<T>(
        &self,
        mut request: Request<T>,
        digest_challenge: Option<String>,
    ) -> Result<Request<T>> {
        unimplemented!()
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
