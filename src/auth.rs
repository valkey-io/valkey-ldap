use std::os::raw::c_int;

use log::{debug, error};
use valkey_module::{AUTH_HANDLED, AUTH_NOT_HANDLED, Context, Status, ValkeyError, ValkeyString};

use crate::configs;
use crate::vkldap;
use crate::vkldap::errors::VkLdapError;

fn auth_reply_callback(
    ctx: &Context,
    username: ValkeyString,
    _: ValkeyString,
    priv_data: Option<&Result<(), VkLdapError>>,
) -> Result<c_int, ValkeyError> {
    if let Some(res) = priv_data {
        match res {
            Ok(_) => match ctx.authenticate_client_with_acl_user(&username) {
                Status::Ok => {
                    debug!("successfully authenticated LDAP user {username}");
                    Ok(AUTH_HANDLED)
                }
                Status::Err => Err(ValkeyError::Str("Failed to authenticate with ACL")),
            },
            Err(err) => {
                debug!("failed to authenticate LDAP user {username}");
                error!("{err}");
                Ok(AUTH_NOT_HANDLED)
            }
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

    let use_bind_mode = configs::is_bind_mode(ctx);

    let user_str = username.to_string();
    let pass_str = password.to_string();

    let mut blocked_client = ctx.block_client_on_auth(auth_reply_callback, Some(free_callback));

    std::thread::spawn(move || {
        let res;
        if use_bind_mode {
            res = vkldap::vk_ldap_bind(&user_str, &pass_str);
        } else {
            res = vkldap::vk_ldap_search_and_bind(&user_str, &pass_str);
        }

        if let Err(e) = blocked_client.set_blocked_private_data(res) {
            error!("failed to set the auth callback result: {e}");
        }
    });

    Ok(AUTH_HANDLED)
}
