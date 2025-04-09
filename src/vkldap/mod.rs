use ldap3::{LdapConn, LdapError};
use valkey_module::{Context as VkModContext, ValkeyError};

pub enum VkLdapError {
    String(String),
}

impl From<LdapError> for VkLdapError {
    fn from(err: LdapError) -> Self {
        VkLdapError::String(format!("hello {err}").to_string())
    }
}

impl From<VkLdapError> for ValkeyError {
    fn from(err: VkLdapError) -> Self {
        let VkLdapError::String(msg) = err;
        ValkeyError::String(msg)
    }
}

type Result<T> = std::result::Result<T, VkLdapError>;

pub struct VkLdapContext<'a> {
    mod_ctx: &'a VkModContext,
    ldap_conn: LdapConn,
}

impl<'a> VkLdapContext<'a> {
    pub fn new<'b: 'a>(ctx: &'b VkModContext, url: &str) -> Result<Self> {
        Ok(VkLdapContext {
            mod_ctx: ctx,
            ldap_conn: LdapConn::new(url)?,
        })
    }

    pub fn bind(&mut self, dn: &str, pass: &str) -> Result<()> {
        let _ = self.ldap_conn.simple_bind(dn, pass)?.success()?;
        self.mod_ctx.log_debug("LDAP bind successful");
        Ok(())
    }
}

impl Drop for VkLdapContext<'_> {
    fn drop(&mut self) {
        match self.ldap_conn.unbind() {
            Ok(_) => (),
            Err(_) => (),
        }
        self.mod_ctx.log_debug("LDAP connection dropped");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
