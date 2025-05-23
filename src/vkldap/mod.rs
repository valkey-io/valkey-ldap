mod connection;
mod context;
pub mod errors;
mod failure_detector;
pub mod server;
pub mod settings;

use connection::VkLdapConnection;
use context::VK_LDAP_CONTEXT;
use errors::VkLdapError;
use server::VkLdapServer;
use settings::VkLdapSettings;
use url::Url;

type Result<T> = std::result::Result<T, VkLdapError>;

pub fn refresh_settings(settings: VkLdapSettings) {
    VK_LDAP_CONTEXT.lock().unwrap().refresh_settings(settings);
}

pub fn clear_server_list() -> () {
    VK_LDAP_CONTEXT.lock().unwrap().clear_server_list();
}

pub fn add_server(server_url: Url) {
    VK_LDAP_CONTEXT.lock().unwrap().add_server(server_url);
}

#[tokio::main]
pub async fn vk_ldap_bind(username: &str, password: &str) -> Result<()> {
    let settings = VK_LDAP_CONTEXT.lock().unwrap().get_settings_copy();
    let prefix = &settings.bind_db_prefix;
    let suffix = &settings.bind_db_suffix;
    let user_dn = format!("{prefix}{username}{suffix}");
    let mut ldap_ctx = VkLdapConnection::new(settings).await?;
    let bind_res = ldap_ctx.bind(user_dn.as_str(), password).await;
    ldap_ctx.close().await;
    bind_res
}

#[tokio::main]
pub async fn vk_ldap_search_and_bind(username: &str, password: &str) -> Result<()> {
    let settings = VK_LDAP_CONTEXT.lock().unwrap().get_settings_copy();
    let mut ldap_ctx = VkLdapConnection::new(settings).await?;
    let user_dn = ldap_ctx.search(username).await?;
    let bind_res = ldap_ctx.bind(user_dn.as_str(), password).await;
    ldap_ctx.close().await;
    bind_res
}

pub fn get_servers_health_status() -> Vec<VkLdapServer> {
    VK_LDAP_CONTEXT.lock().unwrap().get_current_servers()
}

pub fn start_ldap_failure_detector() {
    VK_LDAP_CONTEXT
        .lock()
        .unwrap()
        .start_ldap_failure_detector();
}

pub fn stop_ldap_failure_detector() -> Result<()> {
    VK_LDAP_CONTEXT
        .lock()
        .unwrap()
        .stop_failure_detector_thread()
}
