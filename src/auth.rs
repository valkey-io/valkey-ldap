use std::os::raw::c_int;

use log::{debug, error};
use valkey_module::BlockedClient;
use valkey_module::{AUTH_HANDLED, AUTH_NOT_HANDLED, Context, Status, ValkeyError, ValkeyString};

use crate::configs;
use crate::vkldap;
use crate::vkldap::errors::VkLdapError;

/// Apply ACL rules to a successfully authenticated LDAP user
fn apply_ldap_user_acl(
    ctx: &Context,
    username: &ValkeyString,
    password: &ValkeyString,
    ldap_tokens: &[String],
) -> Result<c_int, ValkeyError> {
    // Build ACL rules: reset commands/keys/channels + defaults + LDAP-provided tokens
    let mut rule_tokens: Vec<String> = Vec::new();

    // Reset all permissions first to avoid accumulation
    rule_tokens.push("resetkeys".to_string());
    rule_tokens.push("resetchannels".to_string());
    rule_tokens.push("-@all".to_string());

    // Add default rules and LDAP tokens
    rule_tokens.extend(configs::get_default_acl_rules(ctx));
    rule_tokens.extend(ldap_tokens.iter().cloned());

    // If ACL fallback is enabled, cache the password
    if configs::is_acl_fallback_enabled(ctx) {
        rule_tokens.push("resetpass".to_string());
        rule_tokens.push(format!(">{}", password.to_string()));
    }

    // Apply ACL SETUSER <username> <rules...>
    let uname = username.to_string();
    let mut args: Vec<String> = Vec::with_capacity(2 + rule_tokens.len());
    args.push("SETUSER".to_string());
    args.push(uname.clone());
    args.extend(rule_tokens);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if let Err(e) = ctx.call("ACL", &arg_refs[..]) {
        error!("failed to set ACL for user {uname}: {e}");
        return Err(ValkeyError::Str("Failed to apply ACL rules"));
    }

    match ctx.authenticate_client_with_acl_user(username) {
        Status::Ok => {
            debug!("successfully authenticated LDAP user {username}");
            Ok(AUTH_HANDLED)
        }
        Status::Err => {
            debug!("failed to authenticate LDAP user {username}");
            error!("LDAP authentication failure");
            if configs::get_return_auth_errors(ctx) {
                Err(ValkeyError::Str("LDAP authentication failure"))
            } else {
                Ok(AUTH_NOT_HANDLED)
            }
        }
    }
}

/// Handle the case where a user is not found in LDAP
fn handle_user_not_found(ctx: &Context, username: &str) -> Result<c_int, ValkeyError> {
    if configs::is_user_exempted_from_ldap(username) {
        return Err(ValkeyError::Str("User not found in LDAP"));
    }

    debug!("user {username} not found in LDAP, deleting from ACL");
    match ctx.call("ACL", &["DELUSER", username]) {
        Ok(_) => debug!("successfully deleted user {username} from ACL"),
        Err(e) => debug!("could not delete user {username} from ACL: {e}"),
    }

    Err(ValkeyError::Str("User not found in LDAP"))
}

/// Handle the case where the LDAP server is unavailable
fn handle_server_unavailable(
    ctx: &Context,
    username: &str,
    err: &VkLdapError,
) -> Result<c_int, ValkeyError> {
    if configs::is_acl_fallback_enabled(ctx) {
        debug!("LDAP server unavailable, falling back to ACL authentication for user {username}");
        Ok(AUTH_NOT_HANDLED)
    } else if configs::get_return_auth_errors(ctx) {
        debug!(
            "LDAP server unavailable and return_auth_errors enabled, returning LDAP error for user {username}"
        );
        Err(ValkeyError::String(err.to_string()))
    } else {
        debug!(
            "LDAP server unavailable and fallback disabled, rejecting authentication for user {username}"
        );
        Err(ValkeyError::String("LDAP server unavailable".to_string()))
    }
}

/// Handle the case where LDAP rejects the credentials
fn handle_credential_rejection(
    ctx: &Context,
    username: &str,
    err: &VkLdapError,
) -> Result<c_int, ValkeyError> {
    // When credentials are rejected, we need to decide whether to delete the user or just clear the password.
    // In bind mode: LDAP error 49 (invalidCredentials) doesn't distinguish between:
    //   - User doesn't exist in LDAP (should delete from ACL)
    //   - User exists but wrong password (could keep in ACL or delete safely - they can re-auth)
    // In search+bind mode: If we reach this point, user was found in search, so it's just wrong password
    //
    // Strategy: Delete the user from ACL to ensure consistency and prevent stale users.
    // Users can always re-authenticate if they exist in LDAP with correct credentials.
    error!("LDAP rejected credentials for user {username}, attempting to delete from ACL");
    match ctx.call("ACL", &["DELUSER", username]) {
        Ok(result) => {
            debug!("ACL DELUSER returned: {result:?}");
            debug!("successfully deleted user {username} from ACL");
        }
        Err(e) => {
            error!("ACL DELUSER failed for user {username}: {e}");
        }
    }

    if configs::get_return_auth_errors(ctx) {
        Err(ValkeyError::String(err.to_string()))
    } else {
        Ok(AUTH_NOT_HANDLED)
    }
}

fn auth_reply_callback(
    ctx: &Context,
    username: ValkeyString,
    password: ValkeyString,
    priv_data: Option<&Result<Vec<String>, VkLdapError>>,
) -> Result<c_int, ValkeyError> {
    let result = match priv_data {
        Some(Ok(ldap_tokens)) => {
            // LDAP authentication succeeded
            apply_ldap_user_acl(ctx, &username, &password, ldap_tokens)
        }
        Some(Err(err)) => {
            // LDAP authentication failed
            let uname = username.to_string();
            debug!("failed to authenticate LDAP user {uname}");
            error!("LDAP authentication failure: {err}");

            if err.is_user_not_found() {
                handle_user_not_found(ctx, &uname)
            } else if err.is_server_unavailable() {
                handle_server_unavailable(ctx, &uname, err)
            } else {
                handle_credential_rejection(ctx, &uname, err)
            }
        }
        None => Err(ValkeyError::Str(
            "Unknown error during authentication, check the server logs",
        )),
    };

    result
}

fn free_callback(_: &Context, _: Result<Vec<String>, VkLdapError>) {}

pub fn ldap_auth_blocking_callback(
    ctx: &Context,
    username: ValkeyString,
    password: ValkeyString,
) -> Result<c_int, ValkeyError> {
    if !configs::is_auth_enabled(ctx) {
        return Ok(AUTH_NOT_HANDLED);
    }

    let user_str = username.to_string();

    // Check if the user is exempted from LDAP authentication
    if configs::is_user_exempted_from_ldap(&user_str) {
        debug!("user {user_str} is exempted from LDAP authentication");
        return Ok(AUTH_NOT_HANDLED);
    }

    debug!("starting authentication for user={username}");

    let use_bind_mode = configs::is_bind_mode(ctx);

    let pass_str = password.to_string();

    let blocked_client = ctx.block_client_on_auth(auth_reply_callback, Some(free_callback));

    let callback =
        move |blocked_client: Option<BlockedClient<Result<Vec<String>, VkLdapError>>>, result| {
            assert!(blocked_client.is_some());
            let mut blocked_client = blocked_client.unwrap();
            if let Err(e) = blocked_client.set_blocked_private_data(result) {
                error!("failed to set the auth callback result: {e}");
            }
        };

    let res = if use_bind_mode {
        vkldap::vk_ldap_bind_and_group_rules(user_str, pass_str, callback, blocked_client)
    } else {
        vkldap::vk_ldap_search_bind_and_group_rules(user_str, pass_str, callback, blocked_client)
    };

    match res {
        Ok(_) => Ok(AUTH_HANDLED),
        Err(err) => {
            error!("failed to submit ldap bind request: {err}");
            if configs::get_return_auth_errors(ctx) {
                Err(ValkeyError::String(err.to_string()))
            } else {
                Ok(AUTH_NOT_HANDLED)
            }
        }
    }
}
