use log::error;
use valkey_module::{InfoContext, ValkeyError, ValkeyResult};
use valkey_module_macros::info_command_handler;

use crate::vkldap::{get_servers_health_status, server::VkLdapServerStatus};

#[info_command_handler]
fn add_ldap_status_section(ctx: &InfoContext, _for_crash_report: bool) -> ValkeyResult<()> {
    let mut builder = ctx.builder().add_section("status");

    let servers_health = match get_servers_health_status() {
        Ok(servers) => servers,
        Err(err) => {
            error!("failed to get the list of servers: {err}");
            return Err(ValkeyError::Str(
                "Failed to get the list of LDAP servers. Check the logs for more details",
            ));
        }
    };

    for (idx, server) in servers_health.iter().enumerate() {
        let mut dict = builder
            .add_dictionary(format!("server_{}", idx).as_str())
            .field("host", server.get_host_string())?;

        match server.get_status() {
            VkLdapServerStatus::HEALTHY => {
                dict = dict.field("status", "healthy")?;

                match server.get_ping_time() {
                    Some(time) => {
                        dict = dict.field(
                            "ping_time_ms",
                            (time.as_micros() as f64 / 1000.0).to_string(),
                        )?;
                    }
                    None => {}
                }
            }
            VkLdapServerStatus::UNHEALTHY(err_msg) => {
                dict = dict.field("status", "unhealthy")?;
                dict = dict.field("error", err_msg.as_str())?;
            }
        };

        builder = dict.build_dictionary()?;
    }

    builder.build_section()?.build_info()?;

    Ok(())
}
