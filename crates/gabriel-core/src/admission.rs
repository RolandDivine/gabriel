//! Who may ask to use a gateway.
//!
//! Metering answers *how much*. This answers *who* — the question the
//! gateway module has carried a "deliberately NOT here yet" note about
//! since it was written. Until now any device that could generate a
//! keypair could ask a gateway to relay for it, and generating a keypair
//! is free.
//!
//! Three mechanisms, checked in a fixed order:
//!
//! 1. **Blocked** wins over everything. A blocked device is refused even
//!    holding a valid invitation, because that is how revocation has to
//!    work — otherwise an invitation you handed out could never be taken
//!    back.
//! 2. **Allowed** is an explicit entry the gateway owner added.
//! 3. **An invitation** is a capability the gateway itself signed. It
//!    names one device, carries an expiry, and may carry a data grant.
//!
//! Anything not matching those falls through to the gateway's default
//! [`AdmissionPolicy`].
//!
//! # Why invitations are verified rather than stored
//!
//! A gateway signs an invitation with the same Ed25519 identity it already
//! announces itself under, so verifying one is checking its own signature.
//! Nothing has to be recorded at issue time, which means invitations can be
//! handed out offline, over the mesh, or read off a screen, and still work
//! on a gateway that has never heard of them.
//!
//! Leaking one is harmless. An invitation names the device it is for, and
//! the gateway request that presents it is signed by the requesting
//! device — so a stolen invitation is useless to the thief, who cannot
//! produce that signature. This is what makes them safe to pass around in
//! the open, which is the entire point of a capability.
//!
//! Replay is bounded by the expiry, and beneath that by the nonce cache
//! the gateway already keeps for requests. An invitation is deliberately
//! reusable until it expires: single-use would mean a device that
//! reconnects after a dropped connection is locked out, which is a worse
//! failure than a capability working twice.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::identity::Identity;
use crate::metering::DeviceId;
use crate::store::Store;
use crate::wire::random_id16;
use crate::Result;

/// Invitation format version, so the shape can change later without
/// older gateways silently misreading a newer token.
pub const INVITATION_VERSION: u8 = 1;

/// Default lifetime for a new invitation: long enough to hand to someone
/// and have them use it later today, short enough that one found on an
/// old screenshot has expired.
pub const DEFAULT_INVITATION_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// What a gateway does with a device it has no explicit entry for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicy {
    /// Anyone may ask. What the gateway did before this module existed,
    /// kept as the default so turning metering on did not also silently
    /// lock out every peer already using a gateway.
    Open,
    /// Only devices explicitly allowed, or presenting a valid invitation.
    InviteOnly,
}

/// Where a device stands with this gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionState {
    Allowed,
    Blocked,
}

impl AdmissionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "allowed" => Some(Self::Allowed),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }
}

/// One entry in the gateway's access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionEntry {
    pub device_id: DeviceId,
    pub state: AdmissionState,
    pub note: Option<String>,
    pub updated_at: i64,
}

/// The decision, and why. The reason is shown to the refused device, so
/// it says enough to be actionable without listing who *is* allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admit { reason: AdmitReason },
    Refuse { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitReason {
    /// On the allow-list.
    Allowed,
    /// Presented an invitation this gateway signed.
    Invited,
    /// The gateway admits anyone.
    OpenPolicy,
}

impl AdmitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "on the allow list",
            Self::Invited => "presented a valid invitation",
            Self::OpenPolicy => "this gateway admits anyone",
        }
    }
}

// ---------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------

/// A capability: "this gateway will relay for this device, until then."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub version: u8,
    /// Which gateway issued it. Checked against the verifying gateway's
    /// own id, so an invitation to one gateway is not accepted by another.
    pub gateway_id: DeviceId,
    /// Which device it admits. The gateway request presenting it must be
    /// signed by this device, which is what makes a leaked invitation
    /// useless to anyone else.
    pub device_id: DeviceId,
    pub issued_unix: u64,
    pub expires_unix: u64,
    /// An allowance that comes with the invitation, applied on first use.
    /// `None` means admitted with no data limit.
    pub data_grant_bytes: Option<u64>,
    /// Makes two invitations to the same device distinguishable.
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInvitation {
    pub invitation: Invitation,
    pub signature: Vec<u8>,
}

impl SignedInvitation {
    /// Issues an invitation, signed by the gateway's own identity.
    pub fn issue(
        gateway: &Identity,
        device_id: DeviceId,
        ttl_secs: u64,
        data_grant_bytes: Option<u64>,
    ) -> Result<Self> {
        let now = now_unix();
        let invitation = Invitation {
            version: INVITATION_VERSION,
            gateway_id: gateway.public_key(),
            device_id,
            issued_unix: now,
            expires_unix: now.saturating_add(ttl_secs),
            data_grant_bytes,
            nonce: random_id16(),
        };
        let signature = gateway.sign(&bincode::serialize(&invitation)?).to_vec();
        Ok(Self { invitation, signature })
    }

    /// Checks an invitation against the gateway verifying it.
    ///
    /// Fails closed on every path, and deliberately does *not* check who
    /// is presenting it — that binding is the caller's job, because the
    /// caller is the one that verified the request signature.
    pub fn verify(&self, gateway_id: &DeviceId, now: u64) -> std::result::Result<(), String> {
        if self.invitation.version != INVITATION_VERSION {
            return Err(format!(
                "invitation format v{} is not understood by this gateway",
                self.invitation.version
            ));
        }
        if &self.invitation.gateway_id != gateway_id {
            return Err("that invitation was issued by a different gateway".to_string());
        }
        if self.invitation.expires_unix <= now {
            return Err("that invitation has expired".to_string());
        }
        // A small allowance for clock skew, then refuse: an invitation
        // dated in the future is either a broken clock or someone trying
        // to extend their own validity window.
        if self.invitation.issued_unix > now.saturating_add(300) {
            return Err("that invitation is dated in the future".to_string());
        }

        let signature: [u8; 64] = self
            .signature
            .clone()
            .try_into()
            .map_err(|_| "malformed invitation signature".to_string())?;
        let payload =
            bincode::serialize(&self.invitation).map_err(|_| "malformed invitation".to_string())?;

        if !Identity::verify(&self.invitation.gateway_id, &payload, &signature) {
            return Err("invitation signature did not verify".to_string());
        }
        Ok(())
    }

    /// A shareable token. Hex rather than base64 to match how every other
    /// identifier in Gabriel is written, at the cost of being longer.
    pub fn to_token(&self) -> Result<String> {
        Ok(format!("gabriel-invite:{}", crate::hex_encode(&bincode::serialize(self)?)))
    }

    pub fn from_token(token: &str) -> std::result::Result<Self, String> {
        let hex = token
            .trim()
            .strip_prefix("gabriel-invite:")
            .ok_or("that is not a Gabriel invitation (it should start with gabriel-invite:)")?;
        let bytes = decode_hex(hex).ok_or("that invitation is not valid hex")?;
        bincode::deserialize(&bytes).map_err(|_| "that invitation is malformed".to_string())
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------
// The control itself
// ---------------------------------------------------------------------

/// The gateway's access list and default policy.
pub struct AdmissionControl {
    store: std::sync::Arc<Store>,
    gateway_id: DeviceId,
    policy: AdmissionPolicy,
}

impl AdmissionControl {
    pub fn new(
        store: std::sync::Arc<Store>,
        gateway_id: DeviceId,
        policy: AdmissionPolicy,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { store, gateway_id, policy })
    }

    pub fn policy(&self) -> AdmissionPolicy {
        self.policy
    }

    pub fn gateway_id(&self) -> DeviceId {
        self.gateway_id
    }

    /// Decides whether `device_id` may open a session.
    ///
    /// Order matters and is fixed: blocked beats everything, then the
    /// allow list, then an invitation, then the default policy.
    pub fn admit(
        &self,
        device_id: &DeviceId,
        invitation: Option<&SignedInvitation>,
    ) -> Result<Admission> {
        let now = now_unix();

        // 1. Blocked wins. Checked first and unconditionally, so an
        //    invitation issued before a device was blocked cannot be used
        //    to get back in -- which is what revocation means.
        if let Some(entry) = self.store.admission_entry(device_id)? {
            match entry.state {
                AdmissionState::Blocked => {
                    return Ok(Admission::Refuse {
                        reason: "this gateway has blocked that device".to_string(),
                    })
                }
                AdmissionState::Allowed => {
                    return Ok(Admission::Admit { reason: AdmitReason::Allowed })
                }
            }
        }

        // 2. An invitation this gateway signed.
        if let Some(signed) = invitation {
            match signed.verify(&self.gateway_id, now) {
                Ok(()) => {
                    if &signed.invitation.device_id != device_id {
                        return Ok(Admission::Refuse {
                            reason: "that invitation was issued to a different device".to_string(),
                        });
                    }
                    // Redeeming records the device and applies whatever
                    // allowance the invitation carried, so the grant does
                    // not have to be handed over separately.
                    self.store.set_admission(
                        device_id,
                        AdmissionState::Allowed,
                        Some("admitted by invitation"),
                        now as i64,
                    )?;
                    if let Some(bytes) = signed.invitation.data_grant_bytes {
                        self.store
                            .set_grant(device_id, bytes, now as i64, Some("from invitation"))?;
                    }
                    return Ok(Admission::Admit { reason: AdmitReason::Invited });
                }
                Err(reason) if self.policy == AdmissionPolicy::InviteOnly => {
                    return Ok(Admission::Refuse { reason })
                }
                // Under an open policy a bad invitation is not fatal --
                // the device would have been admitted anyway.
                Err(_) => {}
            }
        }

        // 3. The default.
        match self.policy {
            AdmissionPolicy::Open => Ok(Admission::Admit { reason: AdmitReason::OpenPolicy }),
            AdmissionPolicy::InviteOnly => Ok(Admission::Refuse {
                reason: "this gateway is invitation-only, and that device has no invitation"
                    .to_string(),
            }),
        }
    }

    pub fn allow(&self, device_id: &DeviceId, note: Option<&str>) -> Result<()> {
        self.store
            .set_admission(device_id, AdmissionState::Allowed, note, now_unix() as i64)
    }

    pub fn block(&self, device_id: &DeviceId, note: Option<&str>) -> Result<()> {
        self.store
            .set_admission(device_id, AdmissionState::Blocked, note, now_unix() as i64)
    }

    /// Removes an explicit entry, returning the device to the default
    /// policy rather than allowing or blocking it.
    pub fn forget(&self, device_id: &DeviceId) -> Result<()> {
        self.store.clear_admission(device_id)
    }

    pub fn entry(&self, device_id: &DeviceId) -> Result<Option<AdmissionEntry>> {
        self.store.admission_entry(device_id)
    }

    pub fn entries(&self) -> Result<Vec<AdmissionEntry>> {
        self.store.all_admissions()
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz_support;
    use std::sync::Arc;

    fn control(policy: AdmissionPolicy) -> (Arc<AdmissionControl>, Identity) {
        let gateway = Identity::generate_ephemeral();
        let store = Arc::new(Store::open_in_memory().unwrap());
        let control = AdmissionControl::new(store, gateway.public_key(), policy);
        (control, gateway)
    }

    fn admitted(result: &Admission) -> bool {
        matches!(result, Admission::Admit { .. })
    }

    // -----------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------

    #[test]
    fn an_open_gateway_admits_a_device_it_has_never_seen() {
        let (control, _) = control(AdmissionPolicy::Open);
        let stranger = Identity::generate_ephemeral().public_key();
        assert!(admitted(&control.admit(&stranger, None).unwrap()));
    }

    #[test]
    fn an_invite_only_gateway_refuses_a_device_it_has_never_seen() {
        let (control, _) = control(AdmissionPolicy::InviteOnly);
        let stranger = Identity::generate_ephemeral().public_key();
        match control.admit(&stranger, None).unwrap() {
            Admission::Refuse { reason } => assert!(reason.contains("invitation-only"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_explicitly_allowed_device_gets_in_under_either_policy() {
        for policy in [AdmissionPolicy::Open, AdmissionPolicy::InviteOnly] {
            let (control, _) = control(policy);
            let device = Identity::generate_ephemeral().public_key();
            control.allow(&device, Some("neighbour")).unwrap();
            assert!(admitted(&control.admit(&device, None).unwrap()), "{policy:?}");
        }
    }

    /// Blocking has to work on a gateway that admits everyone, or it is
    /// not a block at all.
    #[test]
    fn a_blocked_device_is_refused_even_by_an_open_gateway() {
        let (control, _) = control(AdmissionPolicy::Open);
        let device = Identity::generate_ephemeral().public_key();
        control.block(&device, Some("abusive")).unwrap();
        match control.admit(&device, None).unwrap() {
            Admission::Refuse { reason } => assert!(reason.contains("blocked"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn forgetting_a_device_returns_it_to_the_default_policy() {
        let (control, _) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();

        control.allow(&device, None).unwrap();
        assert!(admitted(&control.admit(&device, None).unwrap()));

        control.forget(&device).unwrap();
        assert!(!admitted(&control.admit(&device, None).unwrap()));
        assert!(control.entry(&device).unwrap().is_none());
    }

    // -----------------------------------------------------------------
    // Invitations
    // -----------------------------------------------------------------

    #[test]
    fn a_valid_invitation_admits_a_device_to_an_invite_only_gateway() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();

        let invite = SignedInvitation::issue(&gateway, device, 3600, None).unwrap();
        match control.admit(&device, Some(&invite)).unwrap() {
            Admission::Admit { reason } => assert_eq!(reason, AdmitReason::Invited),
            other => panic!("expected admission, got {other:?}"),
        }
    }

    /// Redeeming records the device, so a reconnect without the token
    /// still works -- otherwise anyone who closed the app would be locked
    /// out until they found their invitation again.
    #[test]
    fn redeeming_an_invitation_records_the_device() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();

        let invite = SignedInvitation::issue(&gateway, device, 3600, None).unwrap();
        control.admit(&device, Some(&invite)).unwrap();

        match control.admit(&device, None).unwrap() {
            Admission::Admit { reason } => assert_eq!(reason, AdmitReason::Allowed),
            other => panic!("a redeemed device should stay admitted, got {other:?}"),
        }
    }

    #[test]
    fn an_invitation_can_carry_a_data_allowance() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();

        let invite = SignedInvitation::issue(&gateway, device, 3600, Some(500_000_000)).unwrap();
        control.admit(&device, Some(&invite)).unwrap();

        let usage = control.store.device_usage(&device).unwrap();
        assert_eq!(usage.granted_bytes, Some(500_000_000));
    }

    /// The property that makes an invitation safe to pass around openly.
    #[test]
    fn an_invitation_is_useless_to_a_device_it_was_not_issued_to() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let invited = Identity::generate_ephemeral().public_key();
        let thief = Identity::generate_ephemeral().public_key();

        let invite = SignedInvitation::issue(&gateway, invited, 3600, None).unwrap();
        match control.admit(&thief, Some(&invite)).unwrap() {
            Admission::Refuse { reason } => {
                assert!(reason.contains("different device"), "{reason}")
            }
            other => panic!("a stolen invitation must not work, got {other:?}"),
        }
    }

    #[test]
    fn an_invitation_from_another_gateway_is_refused() {
        let (control, _) = control(AdmissionPolicy::InviteOnly);
        let other_gateway = Identity::generate_ephemeral();
        let device = Identity::generate_ephemeral().public_key();

        let invite = SignedInvitation::issue(&other_gateway, device, 3600, None).unwrap();
        match control.admit(&device, Some(&invite)).unwrap() {
            Admission::Refuse { reason } => {
                assert!(reason.contains("different gateway"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_expired_invitation_is_refused() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();

        let invite = SignedInvitation::issue(&gateway, device, 0, None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        match control.admit(&device, Some(&invite)).unwrap() {
            Admission::Refuse { reason } => assert!(reason.contains("expired"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_invitation_is_refused() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();

        // Extending your own expiry is the obvious thing to try.
        let mut invite = SignedInvitation::issue(&gateway, device, 60, None).unwrap();
        invite.invitation.expires_unix += 999_999;
        match control.admit(&device, Some(&invite)).unwrap() {
            Admission::Refuse { reason } => assert!(reason.contains("did not verify"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }

        // So is granting yourself more data.
        let mut greedy = SignedInvitation::issue(&gateway, device, 60, Some(1_000)).unwrap();
        greedy.invitation.data_grant_bytes = Some(u64::MAX);
        assert!(!admitted(&control.admit(&device, Some(&greedy)).unwrap()));
    }

    /// Revocation: an invitation already handed out must stop working
    /// once the device is blocked, or it could never be taken back.
    #[test]
    fn blocking_overrides_an_invitation_that_was_already_issued() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();
        let invite = SignedInvitation::issue(&gateway, device, 3600, None).unwrap();

        assert!(admitted(&control.admit(&device, Some(&invite)).unwrap()));

        control.block(&device, Some("changed my mind")).unwrap();
        match control.admit(&device, Some(&invite)).unwrap() {
            Admission::Refuse { reason } => assert!(reason.contains("blocked"), "{reason}"),
            other => panic!("a block must beat an invitation, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Tokens
    // -----------------------------------------------------------------

    #[test]
    fn an_invitation_round_trips_through_its_shareable_token() {
        let gateway = Identity::generate_ephemeral();
        let device = Identity::generate_ephemeral().public_key();
        let invite = SignedInvitation::issue(&gateway, device, 3600, Some(1_000_000)).unwrap();

        let token = invite.to_token().unwrap();
        assert!(token.starts_with("gabriel-invite:"));
        assert_eq!(SignedInvitation::from_token(&token).unwrap(), invite);
        // Surrounding whitespace is what a copy-paste actually produces.
        assert_eq!(SignedInvitation::from_token(&format!("  {token}\n")).unwrap(), invite);
    }

    #[test]
    fn a_malformed_token_is_refused_with_something_actionable() {
        assert!(SignedInvitation::from_token("hello").unwrap_err().contains("gabriel-invite:"));
        assert!(SignedInvitation::from_token("gabriel-invite:zzz")
            .unwrap_err()
            .contains("valid hex"));
        assert!(SignedInvitation::from_token("gabriel-invite:00ff")
            .unwrap_err()
            .contains("malformed"));
    }

    /// Tokens are pasted in by people and arrive over the network, so the
    /// parser is held to the same never-panic bar as every other one.
    #[test]
    fn garbage_tokens_never_panic_the_parser() {
        fuzz_support::assert_never_panics_on_random_bytes(2000, |bytes| {
            let text = String::from_utf8_lossy(bytes);
            let _ = SignedInvitation::from_token(&text);
            let _ = SignedInvitation::from_token(&format!("gabriel-invite:{}", crate::hex_encode(bytes)));
        });
    }

    #[test]
    fn an_unknown_invitation_version_is_refused_rather_than_guessed() {
        let (control, gateway) = control(AdmissionPolicy::InviteOnly);
        let device = Identity::generate_ephemeral().public_key();
        let mut invite = SignedInvitation::issue(&gateway, device, 3600, None).unwrap();
        invite.invitation.version = 99;

        match control.admit(&device, Some(&invite)).unwrap() {
            Admission::Refuse { reason } => assert!(reason.contains("v99"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_access_list_reports_what_was_set() {
        let (control, _) = control(AdmissionPolicy::Open);
        let allowed = Identity::generate_ephemeral().public_key();
        let blocked = Identity::generate_ephemeral().public_key();

        control.allow(&allowed, Some("flatmate")).unwrap();
        control.block(&blocked, None).unwrap();

        let entries = control.entries().unwrap();
        assert_eq!(entries.len(), 2);
        let found = entries.iter().find(|e| e.device_id == allowed).unwrap();
        assert_eq!(found.state, AdmissionState::Allowed);
        assert_eq!(found.note.as_deref(), Some("flatmate"));
        assert_eq!(
            entries.iter().find(|e| e.device_id == blocked).unwrap().state,
            AdmissionState::Blocked
        );
    }
}
