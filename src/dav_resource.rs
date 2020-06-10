use base64;
use base64::write::EncoderWriter as Base64Encoder;
use isahc::http::header;
use isahc::prelude::*;
use isahc::HttpClient;
use std::fmt;
use std::io::Write;

pub struct DavResource {
    pub client: HttpClient,
}

impl DavResource {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}

fn basic_auth<T, U, P>(
    mut request: Request<T>,
    response: &Response<T>,
    username: U,
    password: Option<P>,
) -> Request<T>
where
    U: fmt::Display,
    P: fmt::Display,
{
    let mut header_value = b"Basic ".to_vec();
    {
        let mut encoder = Base64Encoder::new(&mut header_value, base64::STANDARD);
        // The unwraps here are fine because Vec::write* is infallible.
        write!(encoder, "{}:", username).unwrap();
        if let Some(password) = password {
            write!(encoder, "{}", password).unwrap();
        }
    }

    request.headers_mut().insert(
        header::AUTHORIZATION,
        isahc::http::HeaderValue::from_bytes(&header_value).unwrap(),
    );
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;

    #[test]
    fn test_something() {
        let base_url = "/remote.php/dav";
        let m = mock("MKCOL", base_url)
            .with_status(201)
            .with_body("test")
            .create();

        let http_client = HttpClient::new().unwrap();
        let dav_resource = DavResource::new(http_client);
        let uri = format!("{}{}", mockito::server_url(), base_url);
        let request = Request::builder()
            .method("MKCOL")
            .uri(uri)
            .body(())
            .unwrap();
        let mut response = dav_resource.client.send(request).unwrap();
        m.assert();
        assert_eq!(response.text().unwrap(), "test");
        assert_eq!(response.status(), 201);
    }

    #[test]
    fn test_basic_ascii() {
        let original = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();

        let response = Response::new(());

        let request = basic_auth(original, &response, "user", Some("password"));

        assert_eq!(
            request.headers().get(header::AUTHORIZATION).unwrap(),
            "Basic dXNlcjpwYXNzd29yZA=="
        );
    }

    #[test]
    fn test_basic_utf8() {
        todo!()
    }
}
