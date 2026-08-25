//! rustls client/server config, PEM, and ALPN list parse.

use std::io::Cursor;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig,
    SignatureScheme,
};

use crate::error::ErrorTag;

pub fn ensure_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Map `alpn` (`""` = none, `"h2"`, `"http/1.1"`, comma-separated) to rustls bytes.
pub fn alpn_protocols_from_opt(alpn: &str) -> Vec<Vec<u8>> {
    if alpn.is_empty() {
        return Vec::new();
    }
    alpn.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

pub fn parse_server_name(host: &str) -> Result<ServerName<'static>, ErrorTag> {
    ServerName::try_from(host.to_string()).map_err(|_| ErrorTag::InvalidInput)
}

fn webpki_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Add PEM certificates from `pem` into `roots` (append; does not clear).
pub fn add_pem_certs(roots: &mut RootCertStore, pem: &str) -> Result<(), ErrorTag> {
    let mut reader = Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ErrorTag::InvalidInput)?;
    if certs.is_empty() {
        return Err(ErrorTag::InvalidInput);
    }
    for cert in certs {
        roots.add(cert).map_err(|_| ErrorTag::InvalidInput)?;
    }
    Ok(())
}

fn verified_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(webpki_root_store())
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// Verified client config: webpki roots, then optional extra PEM / path.
pub fn verified_config_with_extras(
    ca_pem: Option<&str>,
    ca_path: Option<&str>,
) -> Result<Arc<ClientConfig>, ErrorTag> {
    if ca_pem.is_none() && ca_path.is_none() {
        return Ok(verified_config());
    }
    let mut roots = webpki_root_store();
    if let Some(pem) = ca_pem {
        add_pem_certs(&mut roots, pem)?;
    }
    if let Some(path) = ca_path {
        let pem = std::fs::read_to_string(path).map_err(|e| ErrorTag::from_kind(e.kind()))?;
        add_pem_certs(&mut roots, &pem)?;
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn insecure_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerify))
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// `verify: false`: skip trust/name checks. Record signatures still verified.
#[derive(Debug)]
struct NoCertVerify;

impl ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn client_config(
    verify: bool,
    ca_pem: Option<&str>,
    ca_path: Option<&str>,
    alpn: &str,
) -> Result<Arc<ClientConfig>, ErrorTag> {
    ensure_provider();
    let base = if !verify {
        insecure_config()
    } else {
        verified_config_with_extras(ca_pem, ca_path)?
    };
    let protos = alpn_protocols_from_opt(alpn);
    if protos.is_empty() {
        return Ok(base);
    }
    let mut config = (*base).clone();
    config.alpn_protocols = protos;
    Ok(Arc::new(config))
}

pub fn parse_pem_cert_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ErrorTag> {
    let mut cert_reader = Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ErrorTag::InvalidInput)?;
    if certs.is_empty() {
        return Err(ErrorTag::InvalidInput);
    }
    let mut key_reader = Cursor::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| ErrorTag::InvalidInput)?
        .ok_or(ErrorTag::InvalidInput)?;
    Ok((certs, key))
}

pub fn server_config(
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: &str,
    alpn: &str,
) -> Result<Arc<ServerConfig>, ErrorTag> {
    ensure_provider();
    let (certs, key) = parse_pem_cert_key(cert_pem, key_pem)?;
    let builder = ServerConfig::builder();
    let mut config = if client_ca_pem.is_empty() {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| ErrorTag::InvalidInput)?
    } else {
        let mut roots = RootCertStore::empty();
        add_pem_certs(&mut roots, client_ca_pem)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| ErrorTag::InvalidInput)?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|_| ErrorTag::InvalidInput)?
    };
    let protos = alpn_protocols_from_opt(alpn);
    if !protos.is_empty() {
        config.alpn_protocols = protos;
    }
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocols_from_opt_parses_comma_list() {
        assert!(alpn_protocols_from_opt("").is_empty());
        assert_eq!(alpn_protocols_from_opt("h2"), vec![b"h2".to_vec()]);
        assert_eq!(
            alpn_protocols_from_opt("h2,http/1.1"),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            alpn_protocols_from_opt("h2, http/1.1"),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            alpn_protocols_from_opt("h2,,http/1.1,"),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn parse_pem_rejects_empty_strings() {
        assert_eq!(
            parse_pem_cert_key("", "").unwrap_err(),
            ErrorTag::InvalidInput
        );
    }

    #[test]
    fn parse_pem_rejects_malformed() {
        let err = parse_pem_cert_key(
            "-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nalso-not-valid\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        assert_eq!(err, ErrorTag::InvalidInput);
    }

    #[test]
    fn add_pem_certs_rejects_garbage() {
        let mut roots = RootCertStore::empty();
        assert_eq!(
            add_pem_certs(&mut roots, "not-a-pem").unwrap_err(),
            ErrorTag::InvalidInput
        );
    }

    #[test]
    fn parse_pem_rejects_mismatched_cert_and_key() {
        let cert = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cert.pem"
        ))
        .unwrap();
        let key = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/key2.pem"
        ))
        .unwrap();
        let err = server_config(&cert, &key, "", "").unwrap_err();
        assert_eq!(err, ErrorTag::InvalidInput);
    }

    #[test]
    fn parse_server_name_rejects_empty() {
        assert_eq!(parse_server_name("").unwrap_err(), ErrorTag::InvalidInput);
    }
}
