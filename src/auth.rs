use std::os::raw::c_int;

use crate::configs;
use crate::vkldap;
use crate::vkldap::VkLdapError;
use crate::vkldap::VkLdapSettings;

use log::{debug, error};
use valkey_module::{AUTH_HANDLED, AUTH_NOT_HANDLED, Context, Status, ValkeyError, ValkeyString};

fn auth_reply_callback(
    ctx: &Context,
    username: ValkeyString,
    _: ValkeyString,
    priv_data: Option<&Result<(), VkLdapError>>,
) -> Result<c_int, ValkeyError> {
    if let Some(res) = priv_data {
        match res {
            Ok(_) => {
                debug!("trying to authenticate with ACL: {username}");
                match ctx.authenticate_client_with_acl_user(&username) {
                    Status::Ok => {
                        debug!("successfully authenticated LDAP user: {}", username);
                        Ok(AUTH_HANDLED)
                    }
                    Status::Err => Err(ValkeyError::Str("Failed to authenticate with ACL")),
                }
            }
            Err(e) => Err(ValkeyError::from(e)),
        }
    } else {
        Err(ValkeyError::Str(
            "Unknown error during authentication, check the server logs",
        ))
    }
}

fn free_callback(_: &Context, _: Result<(), VkLdapError>) {}

pub fn ldap_auth_blocking_callback(
    ctx: &Context,
    username: ValkeyString,
    password: ValkeyString,
) -> Result<c_int, ValkeyError> {
    if !configs::is_auth_enabled(ctx) {
        return Ok(AUTH_NOT_HANDLED);
    }

    debug!("starting authentication");

    let settings = VkLdapSettings::new(
        configs::is_starttls_enabled(ctx),
        configs::get_tls_ca_cert_path(ctx),
        configs::get_tls_cert_path(ctx),
        configs::get_tls_key_path(ctx),
        configs::get_bind_dn_prefix(ctx),
        configs::get_bind_dn_suffix(ctx),
    );

    let user_str = username.to_string();
    let pass_str = password.to_string();

    let mut blocked_client = ctx.block_client_on_auth(auth_reply_callback, Some(free_callback));

    std::thread::spawn(move || {
        let res = vkldap::vk_ldap_bind(settings, &user_str, &pass_str);

        if let Err(e) = blocked_client.set_blocked_private_data(res) {
            error!("failed to set the auth callback result: {e}");
        }
    });

    Ok(AUTH_HANDLED)
}
