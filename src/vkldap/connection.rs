use std::fs;

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, SearchEntry};
use log::{debug, warn};
use native_tls::{Certificate, Identity, TlsConnector};
use url::Url;

use crate::{handle_io_error, handle_ldap_error, handle_tls_error};

use super::Result;
use super::context::VK_LDAP_CONTEXT;
use super::errors::VkLdapError;
use super::server::VkLdapServer;
use super::settings::VkLdapSettings;

pub(super) struct VkLdapConnection {
    ldap_handler: Ldap,
    settings: VkLdapSettings,
}

impl VkLdapConnection {
    pub async fn create_ldap_connection(
        settings: &VkLdapSettings,
        server_url: &Url,
    ) -> Result<Ldap> {
        let mut ldap_conn_settings = LdapConnSettings::new();

        let use_starttls = settings.use_starttls;
        let requires_tls = server_url.scheme() == "ldaps" || use_starttls;

        if requires_tls {
            let mut tls_builder = &mut TlsConnector::builder();

            if let Some(path) = &settings.ca_cert_path {
                let ca_cert_bytes =
                    handle_io_error!(fs::read(path), "failed to read CA cert file".to_string());
                let ca_cert = handle_tls_error!(
                    Certificate::from_pem(&ca_cert_bytes),
                    "failed to load CA certificate".to_string()
                );
                tls_builder = tls_builder.add_root_certificate(ca_cert);
            }

            if let Some(cert_path) = &settings.client_cert_path {
                match &settings.client_key_path {
                    None => return Err(VkLdapError::NoTLSKeyPathSet),
                    Some(key_path) => {
                        let cert_bytes = handle_io_error!(
                            fs::read(cert_path),
                            "failed to read client certificate file".to_string()
                        );
                        let key_bytes = handle_io_error!(
                            fs::read(key_path),
                            "failed to read client key file".to_string()
                        );
                        let client_cert = handle_tls_error!(
                            Identity::from_pkcs8(&cert_bytes, &key_bytes),
                            "failed to load client certificate".to_string()
                        );
                        tls_builder = tls_builder.identity(client_cert);
                    }
                }
            }

            let tls_connector = handle_tls_error!(
                tls_builder.build(),
                "failed to setup TLS connection".to_string()
            );

            ldap_conn_settings = ldap_conn_settings.set_connector(tls_connector);
            ldap_conn_settings = ldap_conn_settings.set_starttls(settings.use_starttls);
        }

        match LdapConnAsync::from_url_with_settings(ldap_conn_settings, &server_url).await {
            Ok((conn, handler)) => {
                ldap3::drive!(conn);
                Ok(handler)
            }
            Err(err) => Err(VkLdapError::LdapConnectionError(err)),
        }
    }

    pub async fn new(settings: VkLdapSettings) -> Result<Self> {
        let mut server: VkLdapServer;
        {
            let config = VK_LDAP_CONTEXT.lock().unwrap();
            server = config.find_server()?;
        }

        loop {
            let url = server.get_url_ref();
            debug!("creating LDAP connection to {url}");
            match Self::create_ldap_connection(&settings, url).await {
                Ok(ldap_handler) => {
                    return Ok(VkLdapConnection {
                        ldap_handler,
                        settings,
                    });
                }
                Err(err) => match err {
                    VkLdapError::LdapConnectionError(_) => {
                        let mut config = VK_LDAP_CONTEXT.lock().unwrap();
                        let failover_server = config.failover_server(server, &err);

                        match failover_server {
                            Ok(new_server) => {
                                let url = new_server.get_url_ref();
                                warn!("failing over to server {url}");
                                server = new_server;
                            }
                            Err(err) => {
                                return Err(err);
                            }
                        };
                    }
                    _ => {
                        return Err(err);
                    }
                },
            }
        }
    }

    pub async fn bind(&mut self, user_dn: &str, password: &str) -> Result<()> {
        handle_ldap_error!(
            self.ldap_handler.simple_bind(user_dn, password).await,
            VkLdapError::LdapBindError
        );
        Ok(())
    }

    pub async fn search(&mut self, username: &str) -> Result<String> {
        if let Some(bind_dn) = &self.settings.search_bind_dn {
            if let Some(bind_passwd) = &self.settings.search_bind_passwd {
                handle_ldap_error!(
                    self.ldap_handler.simple_bind(&bind_dn, &bind_passwd).await,
                    VkLdapError::LdapAdminBindError
                );
            }
        }

        let mut base = "";
        if let Some(sbase) = &self.settings.search_base {
            base = &sbase;
        }

        let mut filter = "objectClass=*";
        if let Some(sfilter) = &self.settings.search_filter {
            filter = &sfilter;
        }

        let mut attribute = "uid";
        if let Some(sattribute) = &self.settings.search_attribute {
            attribute = &sattribute;
        }

        let search_filter = format!("(&({filter})({attribute}={username}))");

        let (rs, _res) = handle_ldap_error!(
            self.ldap_handler
                .search(
                    base,
                    self.settings.search_scope,
                    search_filter.as_str(),
                    vec![&self.settings.search_dn_attribute],
                )
                .await,
            VkLdapError::LdapSearchError
        );

        if rs.len() == 0 {
            return Err(VkLdapError::NoLdapEntryFound(search_filter));
        }

        if rs.len() > 1 {
            return Err(VkLdapError::MultipleEntryFound(search_filter));
        }

        let entry = rs
            .into_iter()
            .next()
            .expect("there should be one element in rs");
        let sentry = SearchEntry::construct(entry);

        Ok(sentry.attrs[&self.settings.search_dn_attribute][0].clone())
    }

    pub async fn close(&mut self) {
        let _ = self.ldap_handler.unbind().await;
    }
}
