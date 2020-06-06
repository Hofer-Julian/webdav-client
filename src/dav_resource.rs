use isahc::HttpClient;
pub struct DavResource {
    pub client: HttpClient,
}

impl DavResource {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }
}

#[cfg(test)]
mod tests {
    use super::DavResource;
    use isahc::prelude::*;
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
}
