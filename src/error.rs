pub type Result<T> = std::result::Result<T, Error>;
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid header value: {source}")]
    Io {
        #[from]
        source: isahc::http::header::InvalidHeaderValue,
    },
    #[error("Authentication failed")]
    Authenticate,
}
