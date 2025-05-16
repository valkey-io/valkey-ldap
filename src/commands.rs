use std::collections::BTreeMap;

use valkey_module::{
    Context, ValkeyError, ValkeyResult, ValkeyString, ValkeyValue, redisvalue::ValkeyValueKey,
};

use crate::vkldap::{VkLdapServerStatus, get_servers_health_status};

pub fn ldap_status_command(_ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    if args.len() > 1 {
        return Err(ValkeyError::WrongArity);
    }

    let servers_health = get_servers_health_status();

    let mut map: BTreeMap<ValkeyValueKey, ValkeyValue> = BTreeMap::new();

    let mut status_map: BTreeMap<ValkeyValueKey, ValkeyValue> = BTreeMap::new();

    for server in servers_health.iter() {
        let status = match &server.status {
            VkLdapServerStatus::HEALTHY => "healthy".to_string(),
            VkLdapServerStatus::UNHEALTHY(err_msg) => format!("unhealthy: {err_msg}"),
        };
        let hostname = match server.url.host() {
            Some(host) => host.to_string(),
            None => server.url.to_string(),
        };
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
