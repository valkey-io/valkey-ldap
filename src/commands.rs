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

/// C-callable entry point that runs this crate's collected INFO section
/// handlers against a host-provided info context.
///
/// Redis permits only a single module info callback. When this crate is
/// embedded into a host C module, the host owns that callback so it can also
/// report its own metrics; the dispatcher registered by the generated
/// `RedisModule_OnLoad` (renamed to `LDAP_OnLoad`) is therefore overwritten.
/// The host invokes this shim from its own callback so the LDAP INFO sections
/// are still emitted.
#[cfg(feature = "embed")]
#[unsafe(no_mangle)]
pub extern "C" fn LDAP_AddInfo(
    ctx: *mut valkey_module::raw::RedisModuleInfoCtx,
    for_crash_report: std::os::raw::c_int,
) {
    valkey_module::basic_info_command_handler(&InfoContext::new(ctx), for_crash_report == 1);
}
