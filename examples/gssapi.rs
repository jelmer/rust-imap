//! GSSAPI (Kerberos V5) authentication example.
//!
//! This example expects a working Kerberos environment: a valid TGT in the
//! caller's credential cache (`kinit user@REALM`) and a service principal of
//! the form `imap/<hostname>@REALM` for the IMAP server.
//!
//! Compile with:
//!
//! ```sh
//! cargo run --example gssapi --features gssapi -- mail.example.com 143 user
//! ```

use clap::Parser;
use imap::gssapi::GssapiAuthenticator;

#[derive(Parser)]
struct Args {
    /// IMAP server hostname (must match the Kerberos service principal).
    host: String,
    /// IMAP server port (typically 143 for STARTTLS, 993 for implicit TLS).
    port: u16,
    /// Optional SASL authorization identity.
    #[arg(long)]
    authzid: Option<String>,
}

fn main() {
    let args = Args::parse();

    let client = imap::ClientBuilder::new(&args.host, args.port)
        .connect()
        .expect("could not connect to IMAP server");

    let authenticator = GssapiAuthenticator::new("imap", &args.host, args.authzid)
        .expect("could not initialise GSSAPI client context");

    let mut session = match client.authenticate("GSSAPI", &authenticator) {
        Ok(s) => s,
        Err((e, _)) => {
            if let Some(detail) = authenticator.last_error() {
                eprintln!("GSSAPI authentication failed: {} ({})", e, detail);
            } else {
                eprintln!("authentication failed: {}", e);
            }
            return;
        }
    };

    match session.select("INBOX") {
        Ok(mailbox) => println!("{}", mailbox),
        Err(e) => eprintln!("error selecting INBOX: {}", e),
    }

    session.logout().expect("logout failed");
}
