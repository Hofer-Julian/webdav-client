use crate::error::Result;
use base64;
use base64::write::EncoderWriter as Base64Encoder;
use isahc::http::header;
use isahc::prelude::*;
use std::io::Write;

#[derive(Clone, Debug)]
pub struct AuthHandler {
    domain: Option<String>,
    username: String,
    password: Option<String>,
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
        }
    }

    pub fn basic_auth<T>(
        &self,
        mut request: Request<T>,
        response: &Response<T>,
    ) -> Result<Request<T>> {
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
        let request = auth_handler.basic_auth(original, &response).unwrap();

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
        let request = auth_handler.basic_auth(original, &response).unwrap();
        assert_eq!(
            request.headers().get(header::AUTHORIZATION).unwrap(),
            "Basic dXNlcm5hbWU6cGHDn3dvcmQ="
        );
    }
}
