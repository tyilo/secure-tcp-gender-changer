use std::net::{Ipv4Addr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

use color_eyre::Result;

use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::server::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{
    Certificate, CertificateError, ClientConfig, DistinguishedName, PrivateKey, ServerConfig,
    ServerName,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct SingleCertVerifier {
    certificate: Certificate,
    distinguished_names: Vec<DistinguishedName>,
}

impl SingleCertVerifier {
    fn new(certificate: Certificate) -> Self {
        Self {
            certificate,
            distinguished_names: vec![DistinguishedName::from(vec![])],
        }
    }
}

impl ClientCertVerifier for SingleCertVerifier {
    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &self.distinguished_names
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: std::time::SystemTime,
    ) -> Result<ClientCertVerified, tokio_rustls::rustls::Error> {
        if end_entity == &self.certificate {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

impl ServerCertVerifier for SingleCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &tokio_rustls::rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        if end_entity == &self.certificate {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    Generate,
    Server {
        #[arg(long)]
        proxy_port: u16,

        #[arg(long)]
        incoming_port: u16,

        #[arg(long)]
        server_cert: PathBuf,

        #[arg(long)]
        server_private_key: PathBuf,

        #[arg(long)]
        client_cert: PathBuf,
    },
    Client {
        #[arg(long)]
        proxy_host: String,

        #[arg(long)]
        outgoing_host: String,

        #[arg(long)]
        client_cert: PathBuf,

        #[arg(long)]
        client_private_key: PathBuf,

        #[arg(long)]
        server_cert: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();

    match args.command {
        Command::Generate => {
            for name in ["server", "client"] {
                let cert = rcgen::generate_simple_self_signed(vec!["".to_string()])?;
                std::fs::create_dir_all("certs")?;

                std::fs::write(format!("certs/{name}_cert.der"), cert.serialize_der()?)?;
                std::fs::write(
                    format!("certs/{name}_key.der"),
                    cert.serialize_private_key_der(),
                )?;
            }
        }
        Command::Server {
            proxy_port,
            incoming_port,
            server_cert,
            server_private_key,
            client_cert,
        } => {
            let server_cert = Certificate(std::fs::read(server_cert)?);
            let server_private_key = PrivateKey(std::fs::read(server_private_key)?);
            let client_cert = Certificate(std::fs::read(client_cert)?);

            let client_cert_verifier = Arc::new(SingleCertVerifier::new(client_cert));

            let config = ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(vec![server_cert], server_private_key)?;

            let acceptor = TlsAcceptor::from(Arc::new(config));

            let proxy_listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, proxy_port)).await?;

            let incoming_listener =
                TcpListener::bind((Ipv4Addr::UNSPECIFIED, incoming_port)).await?;

            loop {
                let ((proxy_stream, _), (mut incoming_stream, _)) =
                    tokio::try_join!(proxy_listener.accept(), incoming_listener.accept())?;
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut proxy_stream = acceptor.accept(proxy_stream).await?;

                    tokio::io::copy_bidirectional(&mut proxy_stream, &mut incoming_stream).await?;

                    Ok::<_, color_eyre::Report>(())
                });
            }
        }
        Command::Client {
            proxy_host,
            outgoing_host,
            client_cert,
            client_private_key,
            server_cert,
        } => {
            let client_cert = Certificate(std::fs::read(client_cert)?);
            let client_private_key = PrivateKey(std::fs::read(client_private_key)?);
            let server_cert = Certificate(std::fs::read(server_cert)?);

            let server_cert_verifier = Arc::new(SingleCertVerifier::new(server_cert));
            let config = ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(server_cert_verifier)
                .with_client_auth_cert(vec![client_cert], client_private_key)?;

            let connector = TlsConnector::from(Arc::new(config));

            let proxy_host: Vec<_> = proxy_host.to_socket_addrs()?.collect();
            let outgoing_host: Vec<_> = outgoing_host.to_socket_addrs()?.collect();

            let domain = ServerName::try_from("secure-tcp-gender-changer")?;

            loop {
                let proxy_stream = TcpStream::connect(&*proxy_host).await?;
                let mut proxy_stream = connector.connect(domain.clone(), proxy_stream).await?;
                let outgoing_host = outgoing_host.clone();
                tokio::spawn(async move {
                    let mut outgoing_stream = TcpStream::connect(&*outgoing_host).await?;

                    tokio::io::copy_bidirectional(&mut outgoing_stream, &mut proxy_stream).await?;

                    Ok::<_, color_eyre::Report>(())
                });
            }
        }
    }

    Ok(())
}
