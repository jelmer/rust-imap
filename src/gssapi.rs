//! GSSAPI (Kerberos V5) SASL authentication, per [RFC 4752].
//!
//! This module is only available when the `gssapi` feature is enabled, and
//! requires a system GSSAPI library (e.g. MIT Kerberos or Heimdal) at link
//! time.
//!
//! [RFC 4752]: https://tools.ietf.org/html/rfc4752

use std::cell::RefCell;
use std::error::Error as StdError;
use std::fmt;

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::error::Error as GssError;
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};

use crate::authenticator::Authenticator;

/// "No security layer" bit defined by [RFC 4752 §3.3]. The other layers
/// (integrity, confidentiality) are not implemented here because the IMAP
/// session continues to flow over the underlying TCP/TLS connection
/// unmodified after authentication.
///
/// [RFC 4752 §3.3]: https://tools.ietf.org/html/rfc4752#section-3.3
const SEC_LAYER_NONE: u8 = 0x01;

/// Default maximum message size advertised to the server when negotiating a
/// security layer. The value is otherwise ignored when no security layer is
/// selected.
const DEFAULT_MAX_MSG_SIZE: u32 = 0x00FF_FFFF;

/// An [`Authenticator`] implementing the SASL `GSSAPI` mechanism.
///
/// The authenticator establishes a Kerberos V5 context against a target
/// service (e.g. `imap@mail.example.com`) and then negotiates a SASL security
/// layer with the server. Only the `auth` (no security layer) selection is
/// negotiated; once the authentication exchange completes the IMAP traffic
/// continues to flow over the underlying TCP/TLS connection unmodified.
///
/// ```no_run
/// # #[cfg(all(feature = "native-tls", feature = "gssapi"))]
/// # fn run() -> imap::error::Result<()> {
/// let client = imap::ClientBuilder::new("mail.example.com", 143).connect()?;
/// let authenticator =
///     imap::gssapi::GssapiAuthenticator::new("imap", "mail.example.com", None)
///         .expect("could not initialise GSSAPI context");
/// let mut session = client
///     .authenticate("GSSAPI", &authenticator)
///     .map_err(|(e, _)| e)?;
/// session.select("INBOX")?;
/// # Ok(())
/// # }
/// ```
pub struct GssapiAuthenticator {
    state: RefCell<State>,
}

struct State {
    ctx: ClientCtx,
    /// Optional SASL authorization identity, sent as part of the final
    /// security-layer negotiation message.
    authzid: Option<String>,
    /// Tracks where we are in the SASL exchange. The IMAP `+` continuation
    /// loop only gives us the challenge bytes, so we have to remember whether
    /// we're still establishing the context or whether we're processing the
    /// server's security-layer offer.
    phase: Phase,
    /// Last error from a GSSAPI call. The [`Authenticator`] trait cannot
    /// surface errors directly, so we remember the failure and signal it by
    /// returning an empty response — the server will then reject the
    /// authentication and the caller can inspect this field via
    /// [`GssapiAuthenticator::last_error`].
    error: Option<GssapiAuthError>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// We have not yet called `step` for the first time.
    Initial,
    /// We are exchanging GSSAPI tokens to establish the context.
    Negotiating,
    /// The context is established; the next challenge is the server's
    /// wrapped security-layer offer.
    SecurityLayer,
    /// The exchange is finished from our side.
    Done,
}

/// Errors that can be raised while running the GSSAPI exchange.
#[derive(Debug)]
pub enum GssapiAuthError {
    /// A GSSAPI call (e.g. `Cred::acquire`, `ClientCtx::step`,
    /// `ClientCtx::wrap`) returned an error.
    Gss(GssError),
    /// The server-provided security-layer offer was malformed (must be
    /// exactly four octets when unwrapped).
    InvalidSecurityLayerOffer(usize),
    /// The server's security-layer offer did not include support for the
    /// "no security layer" option, and this authenticator only supports
    /// passing IMAP traffic through unchanged.
    NoSupportedSecurityLayer(u8),
}

impl fmt::Display for GssapiAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GssapiAuthError::Gss(e) => write!(f, "GSSAPI error: {}", e),
            GssapiAuthError::InvalidSecurityLayerOffer(n) => {
                write!(f, "server security-layer offer had {} bytes, expected 4", n)
            }
            GssapiAuthError::NoSupportedSecurityLayer(mask) => write!(
                f,
                "server advertised security-layer mask {:#04x}, which does not include the \"no security layer\" option",
                mask
            ),
        }
    }
}

impl StdError for GssapiAuthError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            GssapiAuthError::Gss(e) => Some(e),
            _ => None,
        }
    }
}

impl From<GssError> for GssapiAuthError {
    fn from(e: GssError) -> Self {
        GssapiAuthError::Gss(e)
    }
}

impl GssapiAuthenticator {
    /// Build an authenticator that targets the given Kerberos service.
    ///
    /// `service` is the SASL service name (typically `"imap"`), `hostname` is
    /// the server's fully qualified hostname as it appears in the service
    /// principal, and `authzid` is an optional SASL authorization identity to
    /// send during the final security-layer exchange.
    ///
    /// The default credentials from the caller's credential cache are used.
    /// If finer control is required, use [`GssapiAuthenticator::with_ctx`]
    /// and pre-build the [`ClientCtx`] yourself.
    pub fn new(
        service: &str,
        hostname: &str,
        authzid: Option<String>,
    ) -> Result<Self, GssapiAuthError> {
        let target = Name::new(
            format!("{}@{}", service, hostname).as_bytes(),
            Some(GSS_NT_HOSTBASED_SERVICE),
        )?
        .canonicalize(Some(GSS_MECH_KRB5))?;

        let mut mechs = OidSet::new();
        mechs.add(GSS_MECH_KRB5)?;
        let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&mechs))?;

        let ctx = ClientCtx::new(
            Some(cred),
            target,
            CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
            Some(GSS_MECH_KRB5),
        );

        Ok(Self::with_ctx(ctx, authzid))
    }

    /// Build an authenticator from an already-prepared [`ClientCtx`].
    ///
    /// This is useful when the caller needs custom credentials, mechanism
    /// OIDs, or context flags beyond what [`GssapiAuthenticator::new`]
    /// configures.
    pub fn with_ctx(ctx: ClientCtx, authzid: Option<String>) -> Self {
        GssapiAuthenticator {
            state: RefCell::new(State {
                ctx,
                authzid,
                phase: Phase::Initial,
                error: None,
            }),
        }
    }

    /// Return any error that the GSSAPI layer raised during the exchange.
    ///
    /// When the underlying [`Authenticator::process`] cannot signal an
    /// error directly, the GSSAPI authenticator records it here and lets the
    /// server abort the authentication. After
    /// [`crate::Client::authenticate`] returns an error, callers can consult
    /// this method to find the GSSAPI cause.
    pub fn last_error(&self) -> Option<String> {
        self.state.borrow().error.as_ref().map(|e| e.to_string())
    }

    fn step(&self, challenge: &[u8]) -> Result<Vec<u8>, GssapiAuthError> {
        let mut state = self.state.borrow_mut();
        match state.phase {
            Phase::Initial => {
                let tok = state.ctx.step(None, None)?;
                state.phase = Phase::Negotiating;
                if state.ctx.is_complete() {
                    state.phase = Phase::SecurityLayer;
                }
                Ok(tok.as_deref().map(<[u8]>::to_vec).unwrap_or_default())
            }
            Phase::Negotiating => {
                let input = if challenge.is_empty() {
                    None
                } else {
                    Some(challenge)
                };
                let tok = state.ctx.step(input, None)?;
                if state.ctx.is_complete() {
                    state.phase = Phase::SecurityLayer;
                }
                Ok(tok.as_deref().map(<[u8]>::to_vec).unwrap_or_default())
            }
            Phase::SecurityLayer => {
                let offer = state.ctx.unwrap(challenge)?;
                let reply = build_security_layer_reply(&offer, state.authzid.as_deref())?;
                let wrapped = state.ctx.wrap(false, &reply)?;
                state.phase = Phase::Done;
                Ok(wrapped.to_vec())
            }
            Phase::Done => Ok(Vec::new()),
        }
    }
}

/// Parse the server's unwrapped security-layer offer and build the client's
/// 4-byte (plus authzid) reply, selecting the "no security layer" option.
fn build_security_layer_reply(
    offer: &[u8],
    authzid: Option<&str>,
) -> Result<Vec<u8>, GssapiAuthError> {
    if offer.len() != 4 {
        return Err(GssapiAuthError::InvalidSecurityLayerOffer(offer.len()));
    }
    let server_mask = offer[0];
    if server_mask & SEC_LAYER_NONE == 0 {
        return Err(GssapiAuthError::NoSupportedSecurityLayer(server_mask));
    }

    let authzid = authzid.unwrap_or("");
    let mut reply = Vec::with_capacity(4 + authzid.len());
    reply.push(SEC_LAYER_NONE);
    let max_size = DEFAULT_MAX_MSG_SIZE.to_be_bytes();
    reply.extend_from_slice(&max_size[1..4]);
    reply.extend_from_slice(authzid.as_bytes());
    Ok(reply)
}

impl Authenticator for GssapiAuthenticator {
    type Response = Vec<u8>;

    fn process(&self, challenge: &[u8]) -> Self::Response {
        match self.step(challenge) {
            Ok(response) => response,
            Err(e) => {
                self.state.borrow_mut().error = Some(e);
                Vec::new()
            }
        }
    }
}

// Re-export `libgssapi` so callers can build their own [`ClientCtx`] for
// [`GssapiAuthenticator::with_ctx`] without depending on the crate directly.
pub use libgssapi;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_layer_reply_no_authzid() {
        let offer = [0x07u8, 0x00, 0xFF, 0xFF];
        let reply = build_security_layer_reply(&offer, None).unwrap();
        assert_eq!(reply, vec![0x01, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn security_layer_reply_with_authzid() {
        let offer = [0x01u8, 0x00, 0x10, 0x00];
        let reply = build_security_layer_reply(&offer, Some("alice")).unwrap();
        let mut expected = vec![0x01, 0xFF, 0xFF, 0xFF];
        expected.extend_from_slice(b"alice");
        assert_eq!(reply, expected);
    }

    #[test]
    fn security_layer_reply_rejects_short_offer() {
        let err = build_security_layer_reply(&[0x01u8, 0x00, 0x10], None).unwrap_err();
        match err {
            GssapiAuthError::InvalidSecurityLayerOffer(3) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn security_layer_reply_rejects_no_none_layer() {
        let err = build_security_layer_reply(&[0x06u8, 0x00, 0x10, 0x00], None).unwrap_err();
        match err {
            GssapiAuthError::NoSupportedSecurityLayer(0x06) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
