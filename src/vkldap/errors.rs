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
    NoHealthyServerAvailable,
    FailedToStopFailuredDetectorThread,
    FailedToShutdownJobScheduler,
    FailedToSendJobToScheduler(String),
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
            VkLdapError::NoHealthyServerAvailable => write!(
                f,
                "all servers set in configuration are unhealthy. Please check the logs for more information"
            ),
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
