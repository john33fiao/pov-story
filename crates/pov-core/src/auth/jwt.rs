use std::{fmt, str};

use base64ct::{Base64UrlUnpadded, Encoding};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::identity::OwnerId;

use super::{
    SecretBytes,
    keyring::{AuthTimestampMicros, KeyId, Keyring},
};

const ACCESS_ISSUER: &str = "urn:pov-story:auth";
const LOCAL_AUDIENCE: &str = "urn:pov-story:api:local";
const REMOTE_AUDIENCE: &str = "urn:pov-story:api:remote";
const ACCESS_LIFETIME_SECONDS: u64 = 600;
const CLOCK_SKEW_SECONDS: u64 = 30;
const MAX_TOKEN_BYTES: usize = 4096;
const HEADER_PREFIX: &str = "{\"alg\":\"EdDSA\",\"kid\":\"";
const HEADER_SUFFIX: &str = "\",\"typ\":\"pov-access+jwt\"}";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthProfile {
    Local,
    Remote,
}

impl AuthProfile {
    pub(crate) const fn audience(self) -> &'static str {
        match self {
            Self::Local => LOCAL_AUDIENCE,
            Self::Remote => REMOTE_AUDIENCE,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }

    pub(crate) const fn parse_persisted(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"local" => Some(Self::Local),
            b"remote" => Some(Self::Remote),
            _ => None,
        }
    }
}

pub(crate) struct IssuedAccessToken {
    encoded: Zeroizing<String>,
    expires_at_seconds: u64,
}

impl IssuedAccessToken {
    pub(crate) fn as_str(&self) -> &str {
        self.encoded.as_str()
    }

    pub(crate) const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }
}

impl fmt::Debug for IssuedAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedAccessToken([REDACTED])")
    }
}

#[derive(Clone, Copy)]
pub(crate) struct VerifiedAccessClaims {
    pub(crate) owner_id: OwnerId,
    pub(crate) session_id: Uuid,
    pub(crate) credential_version: u64,
    pub(crate) profile: AuthProfile,
    pub(crate) expires_at_seconds: u64,
}

impl fmt::Debug for VerifiedAccessClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedAccessClaims([REDACTED])")
    }
}

pub(crate) fn issue_access_token(
    keyring: &Keyring,
    profile: AuthProfile,
    owner_id: OwnerId,
    session_id: Uuid,
    jti: Uuid,
    credential_version: u64,
    now_micros: u64,
) -> Result<IssuedAccessToken, JwtError> {
    if credential_version == 0
        || credential_version > i64::MAX as u64
        || !is_uuid_v4(session_id)
        || !is_uuid_v4(jti)
    {
        return Err(JwtError::InvalidClaims);
    }
    let issued_at_seconds = now_micros / 1_000_000;
    let expires_at_seconds = issued_at_seconds
        .checked_add(ACCESS_LIFETIME_SECONDS)
        .ok_or(JwtError::InvalidClaims)?;
    let header = format!(
        "{HEADER_PREFIX}{}{HEADER_SUFFIX}",
        keyring.active_kid().as_str()
    );
    let claims = format!(
        "{{\"iss\":\"{ACCESS_ISSUER}\",\"aud\":\"{}\",\"sub\":\"{}\",\"sid\":\"{}\",\"jti\":\"{}\",\"ver\":{},\"iat\":{},\"nbf\":{},\"exp\":{}}}",
        profile.audience(),
        owner_id.as_uuid(),
        session_id,
        jti,
        credential_version,
        issued_at_seconds,
        issued_at_seconds,
        expires_at_seconds,
    );
    let encoded_header = Base64UrlUnpadded::encode_string(header.as_bytes());
    let encoded_claims = Base64UrlUnpadded::encode_string(claims.as_bytes());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = keyring.sign(signing_input.as_bytes());
    let encoded_signature = Base64UrlUnpadded::encode_string(&signature);
    let encoded = Zeroizing::new(format!("{signing_input}.{encoded_signature}"));
    if encoded.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::InvalidEncoding);
    }
    Ok(IssuedAccessToken {
        encoded,
        expires_at_seconds,
    })
}

pub(crate) fn verify_access_token(
    keyring: &Keyring,
    profile: AuthProfile,
    token: &SecretBytes,
    now_micros: u64,
) -> Result<VerifiedAccessClaims, JwtError> {
    let token = token.expose_secret();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
        return Err(JwtError::InvalidEncoding);
    }
    let mut parts = token.split(|byte| *byte == b'.');
    let encoded_header = parts.next().ok_or(JwtError::InvalidEncoding)?;
    let encoded_claims = parts.next().ok_or(JwtError::InvalidEncoding)?;
    let encoded_signature = parts.next().ok_or(JwtError::InvalidEncoding)?;
    if parts.next().is_some()
        || encoded_header.is_empty()
        || encoded_claims.is_empty()
        || encoded_signature.is_empty()
    {
        return Err(JwtError::InvalidEncoding);
    }

    let header = decode_canonical_base64(encoded_header)?;
    let kid = parse_header(&header)?;
    let claims = decode_canonical_base64(encoded_claims)?;
    let parsed = parse_claims(&claims, profile)?;
    validate_claim_times(
        parsed.issued_at_seconds,
        parsed.expires_at_seconds,
        now_micros,
    )?;

    let signature = decode_canonical_base64(encoded_signature)?;
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| JwtError::InvalidSignature)?;
    let mut signing_input = Zeroizing::new(Vec::with_capacity(
        encoded_header.len() + encoded_claims.len() + 1,
    ));
    signing_input.extend_from_slice(encoded_header);
    signing_input.push(b'.');
    signing_input.extend_from_slice(encoded_claims);
    let now = AuthTimestampMicros::new(now_micros).map_err(|_| JwtError::InvalidClaims)?;
    if !keyring
        .verify(kid, signing_input.as_slice(), &signature, now)
        .map_err(|_| JwtError::InvalidSignature)?
    {
        return Err(JwtError::InvalidSignature);
    }

    Ok(VerifiedAccessClaims {
        owner_id: parsed.owner_id,
        session_id: parsed.session_id,
        credential_version: parsed.credential_version,
        profile,
        expires_at_seconds: parsed.expires_at_seconds,
    })
}

fn decode_canonical_base64(encoded: &[u8]) -> Result<Vec<u8>, JwtError> {
    let encoded_text = str::from_utf8(encoded).map_err(|_| JwtError::InvalidEncoding)?;
    let decoded =
        Base64UrlUnpadded::decode_vec(encoded_text).map_err(|_| JwtError::InvalidEncoding)?;
    if Base64UrlUnpadded::encode_string(&decoded).as_bytes() != encoded {
        return Err(JwtError::InvalidEncoding);
    }
    Ok(decoded)
}

fn parse_header(header: &[u8]) -> Result<KeyId, JwtError> {
    let header = str::from_utf8(header).map_err(|_| JwtError::InvalidHeader)?;
    let kid = header
        .strip_prefix(HEADER_PREFIX)
        .and_then(|remaining| remaining.strip_suffix(HEADER_SUFFIX))
        .ok_or(JwtError::InvalidHeader)?;
    KeyId::from_stored_bytes(kid.as_bytes()).map_err(|_| JwtError::InvalidHeader)
}

struct ParsedClaims {
    owner_id: OwnerId,
    session_id: Uuid,
    credential_version: u64,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
}

fn parse_claims(claims: &[u8], profile: AuthProfile) -> Result<ParsedClaims, JwtError> {
    let claims = str::from_utf8(claims).map_err(|_| JwtError::InvalidClaims)?;
    let prefix = format!(
        "{{\"iss\":\"{ACCESS_ISSUER}\",\"aud\":\"{}\",\"sub\":\"",
        profile.audience()
    );
    let remaining = claims
        .strip_prefix(&prefix)
        .ok_or(JwtError::InvalidClaims)?;
    let (owner, remaining) = split_once_exact(remaining, "\",\"sid\":\"")?;
    let (session, remaining) = split_once_exact(remaining, "\",\"jti\":\"")?;
    let (jti, remaining) = split_once_exact(remaining, "\",\"ver\":")?;
    let (version, remaining) = split_once_exact(remaining, ",\"iat\":")?;
    let (issued_at, remaining) = split_once_exact(remaining, ",\"nbf\":")?;
    let (not_before, remaining) = split_once_exact(remaining, ",\"exp\":")?;
    let expires_at = remaining.strip_suffix('}').ok_or(JwtError::InvalidClaims)?;

    let owner_uuid = parse_canonical_uuid_v4(owner)?;
    let session_id = parse_canonical_uuid_v4(session)?;
    let _jti = parse_canonical_uuid_v4(jti)?;
    let credential_version = parse_canonical_positive_u64(version)?;
    if credential_version > i64::MAX as u64 {
        return Err(JwtError::InvalidClaims);
    }
    let issued_at_seconds = parse_canonical_u64(issued_at)?;
    let not_before_seconds = parse_canonical_u64(not_before)?;
    let expires_at_seconds = parse_canonical_u64(expires_at)?;
    if issued_at_seconds != not_before_seconds
        || expires_at_seconds
            != issued_at_seconds
                .checked_add(ACCESS_LIFETIME_SECONDS)
                .ok_or(JwtError::InvalidClaims)?
    {
        return Err(JwtError::InvalidClaims);
    }
    Ok(ParsedClaims {
        owner_id: OwnerId::from_verified_uuid(owner_uuid),
        session_id,
        credential_version,
        issued_at_seconds,
        expires_at_seconds,
    })
}

fn split_once_exact<'a>(value: &'a str, separator: &str) -> Result<(&'a str, &'a str), JwtError> {
    let (left, right) = value.split_once(separator).ok_or(JwtError::InvalidClaims)?;
    if left.is_empty() || right.is_empty() {
        return Err(JwtError::InvalidClaims);
    }
    Ok((left, right))
}

fn parse_canonical_uuid_v4(value: &str) -> Result<Uuid, JwtError> {
    if value.len() != 36 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(JwtError::InvalidClaims);
    }
    let parsed = Uuid::parse_str(value).map_err(|_| JwtError::InvalidClaims)?;
    if parsed.to_string() != value || !is_uuid_v4(parsed) {
        return Err(JwtError::InvalidClaims);
    }
    Ok(parsed)
}

fn is_uuid_v4(value: Uuid) -> bool {
    matches!(value.get_version(), Some(uuid::Version::Random))
        && matches!(value.get_variant(), uuid::Variant::RFC4122)
}

fn parse_canonical_positive_u64(value: &str) -> Result<u64, JwtError> {
    let parsed = parse_canonical_u64(value)?;
    if parsed == 0 {
        return Err(JwtError::InvalidClaims);
    }
    Ok(parsed)
}

fn parse_canonical_u64(value: &str) -> Result<u64, JwtError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(JwtError::InvalidClaims);
    }
    value.parse().map_err(|_| JwtError::InvalidClaims)
}

fn validate_claim_times(
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    now_micros: u64,
) -> Result<(), JwtError> {
    let now_seconds = now_micros / 1_000_000;
    if issued_at_seconds > now_seconds.saturating_add(CLOCK_SKEW_SECONDS)
        || now_seconds > expires_at_seconds.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(JwtError::InvalidClaims);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwtError {
    InvalidEncoding,
    InvalidHeader,
    InvalidClaims,
    InvalidSignature,
}

impl fmt::Display for JwtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("access token is invalid")
    }
}

impl std::error::Error for JwtError {}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};

    use super::{
        ACCESS_LIFETIME_SECONDS, AuthProfile, JwtError, issue_access_token, verify_access_token,
    };
    use crate::{
        auth::{
            SecretBytes,
            keyring::{AuthTimestampMicros, Keyring},
        },
        identity::OwnerId,
    };
    use uuid::Uuid;

    const NOW_MICROS: u64 = 1_700_000_000_000_000;

    fn synthetic_keyring(seed: u8) -> Keyring {
        Keyring::from_test_seeds(1, NOW_MICROS - 1, [seed; 32], None).expect("synthetic keyring")
    }

    fn owner() -> OwnerId {
        OwnerId::from_verified_uuid(
            Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("owner UUID"),
        )
    }

    fn session() -> Uuid {
        Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("session UUID")
    }

    fn jti() -> Uuid {
        Uuid::parse_str("55555555-5555-4555-8555-555555555555").expect("JTI UUID")
    }

    #[test]
    fn exact_access_profile_round_trips_and_debug_is_redacted() {
        let keyring = synthetic_keyring(0x31);
        let token = issue_access_token(
            &keyring,
            AuthProfile::Local,
            owner(),
            session(),
            jti(),
            7,
            NOW_MICROS,
        )
        .expect("issued token");
        let claims = verify_access_token(
            &keyring,
            AuthProfile::Local,
            &SecretBytes::new(token.as_str().as_bytes().to_vec()),
            NOW_MICROS,
        )
        .expect("verified token");
        assert_eq!(claims.owner_id, owner());
        assert_eq!(claims.session_id, session());
        assert_eq!(claims.credential_version, 7);
        assert_eq!(claims.profile, AuthProfile::Local);
        assert_eq!(
            claims.expires_at_seconds,
            NOW_MICROS / 1_000_000 + ACCESS_LIFETIME_SECONDS
        );
        assert_eq!(format!("{token:?}"), "IssuedAccessToken([REDACTED])");
        assert_eq!(format!("{claims:?}"), "VerifiedAccessClaims([REDACTED])");
    }

    #[test]
    fn audience_signature_kid_and_time_boundaries_fail_closed() {
        let keyring = synthetic_keyring(0x31);
        let other_keyring = synthetic_keyring(0x41);
        let token = issue_access_token(
            &keyring,
            AuthProfile::Local,
            owner(),
            session(),
            jti(),
            1,
            NOW_MICROS,
        )
        .expect("issued token");
        let secret = || SecretBytes::new(token.as_str().as_bytes().to_vec());
        assert_eq!(
            verify_access_token(&keyring, AuthProfile::Remote, &secret(), NOW_MICROS).unwrap_err(),
            JwtError::InvalidClaims
        );
        assert_eq!(
            verify_access_token(&other_keyring, AuthProfile::Local, &secret(), NOW_MICROS)
                .unwrap_err(),
            JwtError::InvalidSignature
        );
        let expires_at = token.expires_at_seconds();
        assert!(
            verify_access_token(
                &keyring,
                AuthProfile::Local,
                &secret(),
                (expires_at + 30) * 1_000_000,
            )
            .is_ok()
        );
        assert_eq!(
            verify_access_token(
                &keyring,
                AuthProfile::Local,
                &secret(),
                (expires_at + 31) * 1_000_000,
            )
            .unwrap_err(),
            JwtError::InvalidClaims
        );

        let future = issue_access_token(
            &keyring,
            AuthProfile::Local,
            owner(),
            session(),
            jti(),
            1,
            NOW_MICROS + 31_000_000,
        )
        .expect("future token");
        assert_eq!(
            verify_access_token(
                &keyring,
                AuthProfile::Local,
                &SecretBytes::new(future.as_str().as_bytes().to_vec()),
                NOW_MICROS,
            )
            .unwrap_err(),
            JwtError::InvalidClaims
        );
        let _ = AuthTimestampMicros::new(NOW_MICROS).expect("timestamp");
    }

    #[test]
    fn alternate_headers_duplicate_claims_and_noncanonical_base64_are_rejected() {
        let keyring = synthetic_keyring(0x31);
        let token = issue_access_token(
            &keyring,
            AuthProfile::Local,
            owner(),
            session(),
            jti(),
            1,
            NOW_MICROS,
        )
        .expect("issued token");
        let parts: Vec<&str> = token.as_str().split('.').collect();
        let wrong_header = Base64UrlUnpadded::encode_string(
            format!(
                "{{\"alg\":\"none\",\"kid\":\"{}\",\"typ\":\"pov-access+jwt\"}}",
                keyring.active_kid().as_str()
            )
            .as_bytes(),
        );
        let wrong_header_token =
            SecretBytes::new(format!("{}.{}.{}", wrong_header, parts[1], parts[2]).into_bytes());
        assert_eq!(
            verify_access_token(
                &keyring,
                AuthProfile::Local,
                &wrong_header_token,
                NOW_MICROS,
            )
            .unwrap_err(),
            JwtError::InvalidHeader
        );

        let claims = Base64UrlUnpadded::decode_vec(parts[1]).expect("claims");
        let mut claims = String::from_utf8(claims).expect("claims UTF-8");
        claims.insert_str(claims.len() - 1, ",\"exp\":1");
        let duplicate = Base64UrlUnpadded::encode_string(claims.as_bytes());
        let input = format!("{}.{}", parts[0], duplicate);
        let signature = Base64UrlUnpadded::encode_string(&keyring.sign(input.as_bytes()));
        let duplicate_token = SecretBytes::new(format!("{input}.{signature}").into_bytes());
        assert_eq!(
            verify_access_token(&keyring, AuthProfile::Local, &duplicate_token, NOW_MICROS,)
                .unwrap_err(),
            JwtError::InvalidClaims
        );

        let padded =
            SecretBytes::new(format!("{}=.{}.{}", parts[0], parts[1], parts[2]).into_bytes());
        assert_eq!(
            verify_access_token(&keyring, AuthProfile::Local, &padded, NOW_MICROS).unwrap_err(),
            JwtError::InvalidEncoding
        );
    }
}
