use std::collections::BTreeMap;

use log::error;
use valkey_module::{
    Context, ValkeyError, ValkeyResult, ValkeyString, ValkeyValue, redisvalue::ValkeyValueKey,
};

use crate::vkldap::{get_servers_health_status, server::VkLdapServerStatus};

pub fn ldap_status_command(_ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    if args.len() > 1 {
        return Err(ValkeyError::WrongArity);
    }

    let servers_health = match get_servers_health_status() {
        Ok(servers) => servers,
        Err(err) => {
            error!("failed to get the list of servers: {err}");
            return Err(ValkeyError::Str(
                "Failed to get the list of LDAP servers. Check the logs for more details",
            ));
        }
    };

    let mut map: BTreeMap<ValkeyValueKey, ValkeyValue> = BTreeMap::new();

    for server in servers_health.iter() {
        let mut server_map: BTreeMap<ValkeyValueKey, ValkeyValue> = BTreeMap::new();

        match server.get_status() {
            VkLdapServerStatus::HEALTHY => {
                server_map.insert(
                    ValkeyValueKey::String("status".to_string()),
                    ValkeyValue::BulkString("healthy".to_string()),
                );
                match server.get_ping_time() {
                    Some(time) => {
                        server_map.insert(
                            ValkeyValueKey::String("ping_time(ms)".to_string()),
                            ValkeyValue::Float(time.as_micros() as f64 / 1000.0),
                        );
                    }
                    None => {}
                }
            }
            VkLdapServerStatus::UNHEALTHY(err_msg) => {
                server_map.insert(
                    ValkeyValueKey::String("status".to_string()),
                    ValkeyValue::BulkString("unhealthy".to_string()),
                );
                server_map.insert(
                    ValkeyValueKey::String("error".to_string()),
                    ValkeyValue::BulkString(err_msg),
                );
            }
        };

        let hostname = server.get_host_string();
        map.insert(
            ValkeyValueKey::BulkValkeyString(ValkeyString::create(None, hostname)),
            ValkeyValue::OrderedMap(server_map),
        );
    }

    Ok(ValkeyValue::OrderedMap(map))
}
