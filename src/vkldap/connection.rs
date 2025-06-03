use std::collections::VecDeque;
use std::fs;
use std::time::Duration;

use ldap3::exop::WhoAmI;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, SearchEntry};
use log::debug;
use native_tls::{Certificate, Identity, TlsConnector};
use tokio::sync::{Mutex, MutexGuard, Notify};
use url::Url;

use crate::{handle_io_error, handle_ldap_error, handle_tls_error};

use super::Result;
use super::errors::VkLdapError;
use super::server::VkLdapServer;
use super::settings::{VkConnectionSettings, VkLdapSettings};

struct ConnectionQueue {
    queue: VecDeque<VkLdapConnection>,
    epoch: u64,
    size: usize,
}

impl ConnectionQueue {
    fn new() -> ConnectionQueue {
        ConnectionQueue {
            queue: VecDeque::new(),
            epoch: 0,
            size: 0,
        }
    }

    async fn close_connections(&mut self) {
        for conn in self.queue.iter_mut() {
            conn.close().await;
        }
        self.queue.clear();
    }

    async fn reset_connections(
        &mut self,
        server: &VkLdapServer,
        settings: &VkConnectionSettings,
    ) -> Result<()> {
        self.close_connections().await;

        self.epoch += 1;
        self.size = settings.connection_pool_size;

        for _ in 0..self.size {
            match VkLdapConnection::new(&settings, server).await {
                Ok(conn) => self.queue.push_front(conn),
                Err(err) => {
                    self.close_connections().await;
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn has_all_connections(&self) -> bool {
        self.queue.len() == self.size
    }

    fn take(&mut self) -> (VkLdapConnection, u64) {
        assert!(!self.is_empty());
        (self.queue.pop_back().unwrap(), self.epoch)
    }

    fn put(&mut self, conn: VkLdapConnection) {
        self.queue.push_front(conn);
    }

    fn get_epoch(&self) -> u64 {
        self.epoch
    }
}

pub(super) struct VkConnectionPool {
    queue: Mutex<ConnectionQueue>,
    signal: Notify,
    server: VkLdapServer,
}

pub(super) struct VkLdapPoolConnection {
    pub conn: VkLdapConnection,
    pub server: VkLdapServer,
    from_epoch: u64,
}

macro_rules! notify_wait {
    ($notify:expr, $guard:expr) => {{
        let fut = $notify.notified();
        tokio::pin!(fut);
        fut.as_mut().enable();

        // Release the lock
        let lock = MutexGuard::mutex(&$guard);
        drop($guard);

        fut.await;

        // Re-acaquire the lock
        lock.lock().await
    }};
}

impl VkConnectionPool {
    pub async fn new(
        server: VkLdapServer,
        settings: &VkConnectionSettings,
    ) -> (VkConnectionPool, Result<()>) {
        let mut c_queue = ConnectionQueue::new();
        let res = c_queue.reset_connections(&server, settings).await;
        (
            VkConnectionPool {
                queue: Mutex::new(c_queue),
                signal: Notify::new(),
                server,
            },
            res,
        )
    }

    pub async fn refresh_connections(&self, settings: &VkConnectionSettings) -> Result<()> {
        let mut queue = self.queue.lock().await;

        queue.reset_connections(&self.server, settings).await?;

        self.signal.notify_waiters();

        Ok(())
    }

    pub async fn take_connection(&self) -> VkLdapPoolConnection {
        let mut queue = self.queue.lock().await;

        while queue.is_empty() {
            queue = notify_wait!(self.signal, queue);
        }

        let (conn, epoch) = queue.take();
        VkLdapPoolConnection {
            conn,
            server: self.server.clone(),
            from_epoch: epoch,
        }
    }

    pub async fn return_connection(&self, mut pool_conn: VkLdapPoolConnection) {
        let mut queue = self.queue.lock().await;

        if queue.get_epoch() == pool_conn.from_epoch {
            queue.put(pool_conn.conn);
            self.signal.notify_waiters();
        } else {
            pool_conn.conn.close().await;
        }
    }

    pub async fn shutdown(&self) {
        let mut queue = self.queue.lock().await;

        while !queue.has_all_connections() {
            queue = notify_wait!(self.signal, queue);
        }

        queue.close_connections().await
    }
}

pub(super) struct VkLdapConnection {
    ldap_handler: Ldap,
}

impl VkLdapConnection {
    pub async fn new(settings: &VkConnectionSettings, server: &VkLdapServer) -> Result<Self> {
        let url = server.get_url_ref();
        debug!("creating LDAP connection to {url}");

        let ldap_handler = Self::create_ldap_connection(&settings, url).await?;
        Ok(VkLdapConnection { ldap_handler })
    }

    pub async fn ping(&mut self) -> Result<()> {
        handle_ldap_error!(
            self.ldap_handler.extended(WhoAmI).await,
            VkLdapError::LdapServerPingError
        );
        Ok(())
    }

    pub async fn create_ldap_connection(
        settings: &VkConnectionSettings,
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
            ldap_conn_settings = ldap_conn_settings.set_conn_timeout(Duration::from_secs(5));
        }

        match LdapConnAsync::from_url_with_settings(ldap_conn_settings, &server_url).await {
            Ok((conn, handler)) => {
                ldap3::drive!(conn);
                Ok(handler)
            }
            Err(err) => Err(VkLdapError::LdapConnectionError(err)),
        }
    }

    pub async fn bind(&mut self, user_dn: &str, password: &str) -> Result<()> {
        debug!("running ldap bind with DN='{user_dn}'");
        handle_ldap_error!(
            self.ldap_handler.simple_bind(user_dn, password).await,
            VkLdapError::LdapBindError
        );
        Ok(())
    }

    pub async fn search(&mut self, settings: &VkLdapSettings, username: &str) -> Result<String> {
        if let Some(bind_dn) = &settings.search_bind_dn {
            if let Some(bind_passwd) = &settings.search_bind_passwd {
                debug!("running ldap admin bind with DN='{bind_dn}'");
                handle_ldap_error!(
                    self.ldap_handler.simple_bind(&bind_dn, &bind_passwd).await,
                    VkLdapError::LdapAdminBindError
                );
            }
        }

        let mut base = "";
        if let Some(sbase) = &settings.search_base {
            base = &sbase;
        }

        let mut filter = "objectClass=*";
        if let Some(sfilter) = &settings.search_filter {
            filter = &sfilter;
        }

        let mut attribute = "uid";
        if let Some(sattribute) = &settings.search_attribute {
            attribute = &sattribute;
        }

        let search_filter = format!("(&({filter})({attribute}={username}))");
        let scope = settings.search_scope;
        let dn_attribute = &settings.search_dn_attribute;

        debug!(
            "running ldap search with filter='{search_filter}' scope='{:?}' attribute='{dn_attribute}'",
            scope
        );
        let (rs, _res) = handle_ldap_error!(
            self.ldap_handler
                .search(
                    base,
                    settings.search_scope,
                    search_filter.as_str(),
                    vec![dn_attribute],
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

        if !sentry.attrs.contains_key(dn_attribute) {
            return Err(VkLdapError::InvalidDNAttribute(dn_attribute.clone()));
        }

        Ok(sentry.attrs[dn_attribute][0].clone())
    }

    pub async fn close(&mut self) {
        let _ = self.ldap_handler.unbind().await;
    }
}
