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

    let mut status_map: BTreeMap<ValkeyValueKey, ValkeyValue> = BTreeMap::new();

    for server in servers_health.iter() {
        let status = match server.get_status() {
            VkLdapServerStatus::HEALTHY => "healthy".to_string(),
            VkLdapServerStatus::UNHEALTHY(err_msg) => format!("unhealthy: {err_msg}"),
        };
        let hostname = server.get_host_string();
        status_map.insert(
            ValkeyValueKey::BulkValkeyString(ValkeyString::create(None, hostname)),
            ValkeyValue::BulkString(status.to_string()),
        );
    }

    map.insert(
        ValkeyValueKey::BulkValkeyString(ValkeyString::create(None, "Servers_Health")),
        ValkeyValue::OrderedMap(status_map),
    );

    Ok(ValkeyValue::OrderedMap(map))
}
