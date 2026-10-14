//! TLS 1.3 uniquement, certificat client obligatoire, signé par la CA du lab.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::Context;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

pub fn server_config(cert: &str, key: &str, ca: &str) -> anyhow::Result<ServerConfig> {
    let provider = Arc::new(default_provider());
    let certs = read_certs(cert)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key).context(key.to_string())?))?
        .context("aucune clé privée dans le fichier")?;

    let mut roots = RootCertStore::empty();
    for c in read_certs(ca)? {
        roots.add(c)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

fn read_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path).with_context(|| path.to_string())?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(f)).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!certs.is_empty(), "aucun certificat dans {path}");
    Ok(certs)
}

/// CN du certificat client : c'est l'identité utilisée par la politique.
pub fn common_name(der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?.to_string();
    Some(cn)
}
