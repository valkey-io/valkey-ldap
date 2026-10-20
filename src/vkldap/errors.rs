use ldap3::LdapError;
use valkey_module::ValkeyError;

pub enum VkLdapError {
    IOError(String, std::io::Error),
    NoTLSKeyPathSet,
    TLSError(String, native_tls::Error),
    LdapBindError(LdapError),
    LdapAdminBindError(LdapError),
    LdapSearchError(LdapError),
    LdapConnectionError(LdapError),
    LdapServerPingError(LdapError),
    NoLdapEntryFound(String),
    MultipleEntryFound(String),
    InvalidDNAttribute(String),
    NoServerConfigured,
    NoHealthyServerAvailable(Vec<(String, String)>),
    FailedToStopFailuredDetectorThread,
    FailedToShutdownJobScheduler,
    FailedToSendJobToScheduler(String),
    SchedulerNotReady,
}

unsafe impl Send for VkLdapError {}

fn ldap_error_to_string(ldap_err: &LdapError) -> String {
    let msg = ldap_err.to_string();
    // When using Active Directory LDAP API, some error messages might containing a
    // trailing null character. Therefore, we are removing that null character to
    // avoid panics when parsing the string.
    //
    msg.replace('\0', "")
}

impl VkLdapError {
    /// Returns true if the error indicates the user does not exist in LDAP
    pub fn is_user_not_found(&self) -> bool {
        match self {
            // User not found in LDAP search
            VkLdapError::NoLdapEntryFound(_) => true,
            // Check LDAP bind errors for specific result codes indicating user doesn't exist
            VkLdapError::LdapBindError(ldap_err) => {
                // Extract the result code from LdapError
                if let ldap3::LdapError::LdapResult { result } = ldap_err {
                    // RFC 4511 result codes:
                    // - 32 (noSuchObject): The user DN doesn't exist in the directory
                    // - 49 (invalidCredentials): Could be wrong password OR non-existent user
                    //   For code 49, we need to check the diagnostic text for sub-code 525 (0x525)
                    //   which specifically indicates "user not found" in Active Directory
                    match result.rc {
                        32 => true, // noSuchObject - user definitively doesn't exist
                        49 => {
                            // invalidCredentials - check diagnostic text for user-not-found sub-code
                            // Use helper to strip null chars and normalize to lowercase for robust matching
                            let err_text = ldap_error_to_string(ldap_err).to_lowercase();
                            // Check for specific error codes and phrases indicating user not found
                            // AD sub-codes (in hex):
                            // - 525: user not found (safe to delete)
                            // - 52e: invalid credentials/wrong password (DO NOT delete - prevents DoS)
                            // - 530: not permitted to logon at this time
                            // - 531: not permitted to logon at this workstation
                            // - 532: password expired
                            // - 533: account disabled
                            // - 701: account expired
                            // - 773: user must reset password
                            // Only delete on 525 (user not found)
                            err_text.contains(" data 525")
                                || err_text.contains("user not found")
                                || err_text.contains("no such object")
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Returns true if the error shows the attempt was not a wrong password
    /// guess: either the request failed before the user's credentials were
    /// sent to any LDAP server (no servers, module not ready), or the LDAP
    /// service user failed to bind. That bind happens before the user's bind
    /// in search+bind mode, and after the user's bind has already succeeded
    /// when fetching group rules. Errors raised after the user's credentials
    /// may have reached a server (connection errors, timeouts, no healthy
    /// server left after failover, search errors) don't qualify: the module
    /// can't tell whether the client caused them.
    pub fn rules_out_wrong_password(&self) -> bool {
        matches!(
            self,
            VkLdapError::NoServerConfigured
                | VkLdapError::SchedulerNotReady
                | VkLdapError::FailedToSendJobToScheduler(_)
                | VkLdapError::LdapAdminBindError(_)
        )
    }

    /// Returns true if the error indicates the LDAP server is unavailable
    /// This is used to distinguish server unavailability from authentication failures
    pub fn is_server_unavailable(&self) -> bool {
        match self {
            VkLdapError::NoHealthyServerAvailable(_)
            | VkLdapError::LdapConnectionError(_)
            | VkLdapError::NoServerConfigured
            | VkLdapError::SchedulerNotReady => true,
            // The server answered, but with an error about itself rather than
            // about the credentials, so it couldn't judge them
            VkLdapError::LdapBindError(ldap_err)
            | VkLdapError::LdapAdminBindError(ldap_err)
            | VkLdapError::LdapSearchError(ldap_err) => is_server_side_failure(ldap_err),
            _ => false,
        }
    }
}

/// Returns true if the LDAP error reports a timeout or a failure on the
/// server's side instead of a verdict on the request.
fn is_server_side_failure(ldap_err: &LdapError) -> bool {
    match ldap_err {
        LdapError::Timeout { .. } => true,
        // RFC 4511 result codes:
        // - 1 (operationsError): the server failed to process the operation
        // - 3 (timeLimitExceeded): the server-side time limit expired
        // - 51 (busy), 52 (unavailable): the server can't serve the request now
        // - 80 (other): internal server error
        // Client-side codes some servers and proxies relay:
        // - 81 (serverDown), 85 (timeout), 91 (connectError)
        LdapError::LdapResult { result } => {
            matches!(result.rc, 1 | 3 | 51 | 52 | 80 | 81 | 85 | 91)
        }
        _ => false,
    }
}

impl std::fmt::Display for VkLdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VkLdapError::NoTLSKeyPathSet => write!(
                f,
                "no TLS key path specified. Please set the '{}' config",
                cfg_name!("tls_key_path")
            ),
            VkLdapError::IOError(msg, ioerr) => write!(f, "{msg}: {ioerr}"),
            VkLdapError::TLSError(msg, tlserr) => write!(f, "{msg}: {tlserr}"),
            VkLdapError::LdapBindError(ldaperr) => {
                let ldaperr = ldap_error_to_string(ldaperr);
                write!(f, "error in bind operation: {ldaperr}")
            }
            VkLdapError::LdapAdminBindError(ldaperr) => {
                let ldaperr = ldap_error_to_string(ldaperr);
                write!(f, "error in binding admin user: {ldaperr}")
            }
            VkLdapError::LdapSearchError(ldaperr) => {
                let ldaperr = ldap_error_to_string(ldaperr);
                write!(f, "failed to search ldap user: {ldaperr}")
            }
            VkLdapError::LdapConnectionError(ldaperr) => {
                let ldaperr = ldap_error_to_string(ldaperr);
                write!(f, "LDAP connection failure: {ldaperr}")
            }
            VkLdapError::LdapServerPingError(ldaperr) => {
                let ldaperr = ldap_error_to_string(ldaperr);
                write!(
                    f,
                    "failed to run WhoAmI command on the ldap server: {ldaperr}"
                )
            }
            VkLdapError::NoLdapEntryFound(filter) => {
                write!(f, "search filter '{filter}' returned no entries")
            }
            VkLdapError::MultipleEntryFound(filter) => {
                write!(f, "search filter '{filter}' returned multiple entries")
            }
            VkLdapError::InvalidDNAttribute(attribute) => {
                write!(
                    f,
                    "the user entry does not have the '{attribute}' attribute to get the user DN"
                )
            }
            VkLdapError::NoServerConfigured => write!(
                f,
                "no server set in configuration. Please set the '{}' config option",
                cfg_name!("servers")
            ),
            VkLdapError::NoHealthyServerAvailable(servers) => {
                let detail: Vec<String> = servers
                    .iter()
                    .map(|(url, reason)| format!("{url} ({reason})"))
                    .collect();
                write!(f, "all servers are unhealthy: {}", detail.join(", "))
            }
            VkLdapError::FailedToStopFailuredDetectorThread => write!(
                f,
                "failed to wait for the failure detector thread to finish"
            ),
            VkLdapError::FailedToShutdownJobScheduler => write!(
                f,
                "failed to shutdown job scheduler. Please check the logs for more information"
            ),
            VkLdapError::FailedToSendJobToScheduler(errmsg) => {
                write!(f, "failed to send job to scheduler: {errmsg}")
            }
            VkLdapError::SchedulerNotReady => write!(
                f,
                "LDAP scheduler is not ready. Module may still be initializing"
            ),
        }
    }
}

impl From<&VkLdapError> for ValkeyError {
    fn from(err: &VkLdapError) -> Self {
        err.into()
    }
}

impl VkLdapError {
    pub(super) fn is_ldap_connection_error(err: &LdapError) -> bool {
        match err {
            LdapError::LdapResult { .. }
            | LdapError::FilterParsing
            | LdapError::DecodingUTF8
            | LdapError::InvalidScopeString(_)
            | LdapError::AddNoValues
            | LdapError::AdapterInit(_) => false,
            _ => true,
        }
    }
}

#[macro_export]
macro_rules! handle_io_error {
    ($expr:expr, $errmsg:expr) => {
        match $expr {
            Ok(res) => res,
            Err(err) => return Err(VkLdapError::IOError($errmsg, err)),
        }
    };
}

#[macro_export]
macro_rules! handle_tls_error {
    ($expr:expr, $errmsg:expr) => {
        match $expr {
            Ok(res) => res,
            Err(err) => return Err(VkLdapError::TLSError($errmsg, err)),
        }
    };
}

#[macro_export]
macro_rules! handle_ldap_error {
    ($expr:expr, $errtype:expr) => {
        match $expr {
            Ok(res) => match res.success() {
                Ok(res) => res,
                Err(err) => return Err($errtype(err)),
            },
            Err(err) => {
                if VkLdapError::is_ldap_connection_error(&err) {
                    return Err(VkLdapError::LdapConnectionError(err));
                } else {
                    return Err($errtype(err));
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3::{LdapError, LdapResult};

    fn ldap_result_error(rc: u32) -> LdapError {
        LdapError::LdapResult {
            result: LdapResult {
                rc,
                matched: String::new(),
                text: String::new(),
                refs: vec![],
                ctrls: vec![],
            },
        }
    }

    #[test]
    fn rules_out_wrong_password() {
        assert!(VkLdapError::NoServerConfigured.rules_out_wrong_password());
        assert!(VkLdapError::SchedulerNotReady.rules_out_wrong_password());
        assert!(VkLdapError::LdapAdminBindError(ldap_result_error(49)).rules_out_wrong_password());
    }

    #[test]
    fn may_be_wrong_password() {
        // Wrong password, unwillingToPerform (e.g. empty password), errors
        // during or after the user's bind, and ambiguous search results all
        // stay counted
        assert!(!VkLdapError::LdapBindError(ldap_result_error(49)).rules_out_wrong_password());
        assert!(!VkLdapError::LdapBindError(ldap_result_error(53)).rules_out_wrong_password());
        assert!(!VkLdapError::LdapSearchError(ldap_result_error(1)).rules_out_wrong_password());
        assert!(!VkLdapError::NoHealthyServerAvailable(vec![]).rules_out_wrong_password());
        assert!(!VkLdapError::MultipleEntryFound("uid=x*".to_string()).rules_out_wrong_password());
        assert!(!VkLdapError::NoLdapEntryFound("uid=x".to_string()).rules_out_wrong_password());
    }

    #[test]
    fn server_side_failures_are_unavailable() {
        for rc in [1, 3, 51, 52, 80, 81, 85, 91] {
            assert!(VkLdapError::LdapBindError(ldap_result_error(rc)).is_server_unavailable());
            assert!(VkLdapError::LdapAdminBindError(ldap_result_error(rc)).is_server_unavailable());
            assert!(VkLdapError::LdapSearchError(ldap_result_error(rc)).is_server_unavailable());
            assert!(!VkLdapError::LdapBindError(ldap_result_error(rc)).is_user_not_found());
        }
    }

    #[test]
    fn credential_verdicts_are_not_unavailable() {
        // invalidCredentials, insufficientAccessRights, noSuchObject,
        // unwillingToPerform and success mean the server judged the request
        for rc in [0, 32, 49, 50, 53] {
            assert!(!VkLdapError::LdapBindError(ldap_result_error(rc)).is_server_unavailable());
            assert!(!VkLdapError::LdapSearchError(ldap_result_error(rc)).is_server_unavailable());
        }
        assert!(!VkLdapError::NoLdapEntryFound("uid=x".to_string()).is_server_unavailable());
        assert!(!VkLdapError::MultipleEntryFound("uid=x*".to_string()).is_server_unavailable());
    }
}
