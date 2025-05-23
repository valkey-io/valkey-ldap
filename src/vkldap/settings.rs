use ldap3::Scope;

use crate::configs::LdapSearchScope;

impl From<LdapSearchScope> for Scope {
    fn from(value: LdapSearchScope) -> Self {
        match value {
            LdapSearchScope::Base => Scope::Base,
            LdapSearchScope::OneLevel => Scope::OneLevel,
            LdapSearchScope::SubTree => Scope::Subtree,
        }
    }
}

#[derive(Clone)]
pub struct VkLdapSettings {
    pub bind_db_prefix: String,
    pub bind_db_suffix: String,
    pub search_base: Option<String>,
    pub search_scope: Scope,
    pub search_filter: Option<String>,
    pub search_attribute: Option<String>,
    pub search_bind_dn: Option<String>,
    pub search_bind_passwd: Option<String>,
    pub search_dn_attribute: String,
}

impl VkLdapSettings {
    pub fn new(
        bind_db_prefix: String,
        bind_db_suffix: String,
        search_base: Option<String>,
        search_scope: LdapSearchScope,
        search_filter: Option<String>,
        search_attribute: Option<String>,
        search_bind_dn: Option<String>,
        search_bind_passwd: Option<String>,
        search_dn_attribute: String,
    ) -> Self {
        Self {
            bind_db_prefix,
            bind_db_suffix,
            search_base,
            search_scope: search_scope.into(),
            search_filter,
            search_attribute,
            search_bind_dn,
            search_bind_passwd,
            search_dn_attribute,
        }
    }
}

impl Default for VkLdapSettings {
    fn default() -> Self {
        Self {
            bind_db_prefix: Default::default(),
            bind_db_suffix: Default::default(),
            search_base: Default::default(),
            search_scope: Scope::Subtree,
            search_filter: Default::default(),
            search_attribute: Default::default(),
            search_bind_dn: Default::default(),
            search_bind_passwd: Default::default(),
            search_dn_attribute: Default::default(),
        }
    }
}

#[derive(Clone)]
pub struct VkConnectionSettings {
    pub use_starttls: bool,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub connection_pool_size: usize,
}

impl VkConnectionSettings {
    pub fn new(
        use_starttls: bool,
        ca_cert_path: Option<String>,
        client_cert_path: Option<String>,
        client_key_path: Option<String>,
        connection_pool_size: usize,
    ) -> Self {
        Self {
            use_starttls,
            ca_cert_path,
            client_cert_path,
            client_key_path,
            connection_pool_size,
        }
    }
}

impl Default for VkConnectionSettings {
    fn default() -> Self {
        Self {
            use_starttls: Default::default(),
            ca_cert_path: Default::default(),
            client_cert_path: Default::default(),
            client_key_path: Default::default(),
            connection_pool_size: 0,
        }
    }
}
