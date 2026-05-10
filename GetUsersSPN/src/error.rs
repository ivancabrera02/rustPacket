use thiserror::Error;

#[derive(Debug, Error)]
pub enum KrbError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ASN.1 parse error: {0}")]
    Parse(String),

    #[error("Kerberos error code {0}: {1}")]
    KrbErrorCode(i64, String),

    #[error("Unsupported etype: {0}")]
    UnsupportedEtype(i64),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Network error: {0}")]
    Network(String),
}

/// KRB5 error codes → human description
pub fn krb_error_string(code: i64) -> &'static str {
    match code {
        6  => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7  => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        12 => "KDC_ERR_POLICY",
        14 => "KDC_ERR_ETYPE_NOSUPP",
        18 => "KDC_ERR_CLIENT_REVOKED (account disabled/locked)",
        23 => "KDC_ERR_KEY_EXPIRED",
        24 => "KDC_ERR_PREAUTH_FAILED (wrong password)",
        25 => "KDC_ERR_PREAUTH_REQUIRED",
        31 => "KRB_AP_ERR_SKEW (clock skew too great)",
        37 => "KRB_ERR_RESPONSE_TOO_BIG",
        _  => "Unknown KRB5 error",
    }
}
