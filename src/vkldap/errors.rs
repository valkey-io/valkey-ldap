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

    /// Returns true if the error indicates the LDAP server is unavailable
    /// This is used to distinguish server unavailability from authentication failures
    pub fn is_server_unavailable(&self) -> bool {
        matches!(
            self,
            VkLdapError::NoHealthyServerAvailable
                | VkLdapError::LdapConnectionError(_)
                | VkLdapError::NoServerConfigured
                | VkLdapError::SchedulerNotReady
        )
    }
}

impl std::fmt::Display for VkLdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VkLdapError::NoTLSKeyPathSet => write!(
                f,
                "no TLS key path specified. Please set the path for ldap.tls_key_path config"
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
                "no server set in configuration. Please set ldap.servers config option"
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
