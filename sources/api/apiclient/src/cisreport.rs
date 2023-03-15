use snafu::ResultExt;
use std::path::Path;

/// Requests a CIS complaince report through the API.
pub async fn get_report<P>(
    socket_path: P,
    format: Option<String>,
    level: Option<i32>,
) -> Result<String>
where
    P: AsRef<Path>,
{
    let method = "GET";
    let uri;

    let mut query = Vec::new();
    if let Some(query_format) = format {
        query.push(format!("format={}", query_format));
    }
    if let Some(query_level) = level {
        query.push(format!("level={}", query_level));
    }

    if !query.is_empty() {
        let mut query_string = "".to_string();
        let mut first = true;
        for query_arg in query {
            if !first {
                query_string = format!("{}&{}", query_string, query_arg).to_string();
            } else {
                first = false;
                query_string = query_arg.to_string();
            }
        }
        uri = format!("/cis-report?{}", query_string);
    } else {
        uri = "/cis-report".to_string();
    }

    let (_status, body) = crate::raw_request(&socket_path, &uri, method, None)
        .await
        .context(error::RequestSnafu { uri, method })?;

    Ok(body)
}

mod error {
    use snafu::Snafu;

    #[derive(Debug, Snafu)]
    #[snafu(visibility(pub(super)))]
    pub enum Error {
        #[snafu(display("Failed {} request to '{}': {}", method, uri, source))]
        Request {
            method: String,
            uri: String,
            #[snafu(source(from(crate::Error, Box::new)))]
            source: Box<crate::Error>,
        },
    }
}
pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;
