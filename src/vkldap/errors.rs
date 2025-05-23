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
    NoLdapEntryFound(String),
    MultipleEntryFound(String),
    NoServerConfigured,
    NoHealthyServerAvailable,
    FailedToStopFailuredDetectorThread,
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
                write!(f, "error in bind operation: {ldaperr}")
            }
            VkLdapError::LdapAdminBindError(ldaperr) => {
                write!(f, "error in binding admin user: {ldaperr}")
            }
            VkLdapError::LdapSearchError(ldaperr) => {
                write!(f, "failed to search ldap user: {ldaperr}")
            }
            VkLdapError::LdapConnectionError(ldaperr) => {
                write!(f, "failed to establish an LDAP connection: {ldaperr}")
            }
            VkLdapError::NoLdapEntryFound(filter) => {
                write!(f, "search filter '{filter}' returned no entries")
            }
            VkLdapError::MultipleEntryFound(filter) => {
                write!(f, "search filter '{filter}' returned multiple entries")
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
        }
    }
}

impl From<&VkLdapError> for ValkeyError {
    fn from(err: &VkLdapError) -> Self {
        err.into()
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
            Err(err) => return Err($errtype(err)),
        }
    };
}
