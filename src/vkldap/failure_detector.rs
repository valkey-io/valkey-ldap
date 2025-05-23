use std::time::Duration;

use futures::future;
use log::debug;

use super::Result;
use super::connection::VkLdapConnection;
use super::context::VK_LDAP_CONTEXT;
use super::server::{VkLdapServer, VkLdapServerStatus};
use super::settings::VkLdapSettings;

async fn check_server_health_async(
    settings: &VkLdapSettings,
    server: VkLdapServer,
) -> (VkLdapServer, Result<()>) {
    match VkLdapConnection::create_ldap_connection(settings, server.get_url_ref()).await {
        Ok(mut handler) => {
            let _ = handler.unbind().await;
            (server, Ok(()))
        }
        Err(err) => (server, Err(err)),
    }
}

async fn check_servers_health(
    servers: Vec<VkLdapServer>,
    settings: VkLdapSettings,
) -> Vec<(VkLdapServer, Result<()>)> {
    let mut futures = Vec::new();

    for server in servers {
        let check_health_fut = check_server_health_async(&settings, server);
        futures.push(check_health_fut);
    }

    future::join_all(futures).await
}

#[tokio::main]
pub(super) async fn failure_detector_loop() -> () {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let settings;
        {
            settings = VK_LDAP_CONTEXT.lock().unwrap().get_settings_copy();
        }

        let servers;
        {
            servers = VK_LDAP_CONTEXT.lock().unwrap().get_current_servers();
        }

        let status_res = check_servers_health(servers, settings).await;
        {
            let mut config = VK_LDAP_CONTEXT.lock().unwrap();
            for (server, res) in status_res {
                match res {
                    Ok(_) => config.update_server_status(server, VkLdapServerStatus::HEALTHY),
                    Err(err) => {
                        let err_msg = err.to_string();
                        config.update_server_status(server, VkLdapServerStatus::UNHEALTHY(err_msg));
                    }
                }
            }
        }

        if VK_LDAP_CONTEXT
            .lock()
            .unwrap()
            .should_stop_failure_detector_thread()
        {
            debug!("exiting failure detector loop");
            return ();
        }
    }
}
