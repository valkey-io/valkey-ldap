mod connection;
mod context;
pub mod errors;
pub mod failure_detector;
pub mod scheduler;
pub mod server;
pub mod settings;

use errors::VkLdapError;
use log::error;
use scheduler::CallbackTrait;
use server::VkLdapServer;
use settings::{VkConnectionSettings, VkLdapSettings};
use url::Url;

type Result<T> = std::result::Result<T, VkLdapError>;

pub fn refresh_ldap_settings(settings: VkLdapSettings) {
    if !scheduler::is_scheduler_ready() {
        return ();
    }

    let res = scheduler::submit_sync_task(context::refresh_ldap_settings(settings));
    if let Err(err) = res {
        error!("refresh ldap settings returned an error: {err}");
    }
}

pub fn refresh_connection_settings(settings: VkConnectionSettings) {
    if !scheduler::is_scheduler_ready() {
        return ();
    }

    let res = scheduler::submit_sync_task(context::refresh_connection_settings(settings));
    if let Err(err) = res {
        error!("refresh ldap settings returned an error: {err}");
    }
}

pub fn clear_server_list() -> Result<()> {
    if !scheduler::is_scheduler_ready() {
        return Ok(());
    }
    scheduler::submit_sync_task(context::clear_server_list())
}

pub fn add_server(server_url: Url) -> Result<()> {
    if !scheduler::is_scheduler_ready() {
        return Ok(());
    }
    scheduler::submit_sync_task(context::add_server(server_url))
}

pub fn get_servers_health_status() -> Result<Vec<VkLdapServer>> {
    if !scheduler::is_scheduler_ready() {
        return Ok(Vec::new());
    }

    scheduler::submit_sync_task(context::get_servers_health_status())
}

pub fn vk_ldap_bind<C, T>(username: String, password: String, callback: C, data: T) -> Result<()>
where
    T: 'static + Send,
    C: CallbackTrait<T, Result<()>>,
{
    if !scheduler::is_scheduler_ready() {
        return Ok(());
    }

    scheduler::submit_async_task(context::ldap_bind(username, password), callback, data)
}

pub fn vk_ldap_search_and_bind<C, T>(
    username: String,
    password: String,
    callback: C,
    data: T,
) -> Result<()>
where
    T: 'static + Send,
    C: CallbackTrait<T, Result<()>>,
{
    if !scheduler::is_scheduler_ready() {
        return Ok(());
    }

    scheduler::submit_async_task(
        context::ldap_search_and_bind(username, password),
        callback,
        data,
    )
}
