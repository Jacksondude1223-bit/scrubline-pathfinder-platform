//! Verified TLS client shared by the Rust operator tools.
use crate::Result;
use reqwest::{blocking::Client, Certificate};
use std::{path::Path, time::Duration};
pub fn client(ca_file: Option<&Path>, timeout: Duration) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .min_tls_version(reqwest::tls::Version::TLS_1_2);
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|e| format!("reading CA bundle: {e}"))?;
        let certs =
            Certificate::from_pem_bundle(&pem).map_err(|e| format!("reading CA bundle: {e}"))?;
        if certs.is_empty() {
            return Err(format!(
                "CA bundle {} contains no certificates",
                path.display()
            ));
        }
        // The Go client replaces system roots when a private CA bundle is supplied.
        builder = builder.tls_built_in_root_certs(false);
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build().map_err(|e| e.to_string())
}
