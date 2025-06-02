use lazy_static::lazy_static;
use std::{sync::Arc, time::Duration};

use log::info;
use tokio::sync::Mutex;
use url::Url;

use super::{
    Result,
    connection::{VkConnectionPool, VkLdapConnection, VkLdapPoolConnection},
    errors::VkLdapError,
    server::{VkLdapServer, VkLdapServerStatus},
    settings::{VkConnectionSettings, VkLdapSettings},
};

struct VkLdapContext {
    servers: Vec<VkLdapServer>,
    conn_pools: Vec<Arc<VkConnectionPool>>,
    ldap_settings: VkLdapSettings,
    connection_settings: VkConnectionSettings,
}

impl VkLdapContext {
    fn new() -> VkLdapContext {
        VkLdapContext {
            servers: Vec::new(),
            conn_pools: Vec::new(),
            ldap_settings: VkLdapSettings::default(),
            connection_settings: VkConnectionSettings::default(),
        }
    }

    fn get_ldap_settings(&self) -> VkLdapSettings {
        self.ldap_settings.clone()
    }

    fn get_connection_settings(&self) -> VkConnectionSettings {
        self.connection_settings.clone()
    }

    fn refresh_ldap_settings(&mut self, settings: VkLdapSettings) {
        self.ldap_settings = settings
    }

    fn refresh_connection_settings(&mut self, settings: VkConnectionSettings) {
        self.connection_settings = settings;
    }

    fn clear_server_list(&mut self) -> Vec<Arc<VkConnectionPool>> {
        self.servers.clear();

        let mut pools = Vec::with_capacity(self.conn_pools.len());
        for pool in self.conn_pools.iter() {
            pools.push(Arc::clone(pool));
        }

        self.conn_pools.clear();
        pools
    }

    fn new_server(&self, server_url: Url) -> VkLdapServer {
        let server_id = self.servers.len();
        VkLdapServer::new(server_url, server_id, VkLdapServerStatus::HEALTHY)
    }

    fn add_server(&mut self, server: VkLdapServer, pool: VkConnectionPool) {
        self.servers.push(server);
        self.conn_pools.push(Arc::new(pool));
    }

    fn get_connection_pool(&self, server: &VkLdapServer) -> Arc<VkConnectionPool> {
        Arc::clone(&self.conn_pools[server.get_id()])
    }

    fn get_current_servers(&self) -> Vec<VkLdapServer> {
        let mut res: Vec<VkLdapServer> = Vec::new();
        self.servers.iter().for_each(|s| res.push(s.clone()));
        res
    }

    fn update_server_status(
        &mut self,
        server: &VkLdapServer,
        status: VkLdapServerStatus,
        ping_time: Option<Duration>,
    ) {
        if server.get_id() >= self.servers.len() {
            return ();
        }

        let server = &mut self.servers[server.get_id()];
        if server.get_url_ref() != server.get_url_ref() {
            return ();
        }

        if server.get_status() != status {
            let pre_status = server.get_status();
            let url = server.get_url_ref();
            info!("transition server {url} {pre_status} -> {status}");
            server.set_status(status);
        } else {
            server.set_status(status);
        }

        server.set_ping_time(ping_time)
    }

    fn find_server(&self) -> Result<VkLdapServer> {
        if self.servers.is_empty() {
            return Err(VkLdapError::NoServerConfigured);
        }

        for server in self.servers.iter() {
            if server.is_healthy() {
                return Ok(server.clone());
            }
        }

        Err(VkLdapError::NoHealthyServerAvailable)
    }
}

lazy_static! {
    static ref VK_LDAP_CONTEXT: Mutex<VkLdapContext> = Mutex::new(VkLdapContext::new());
}

pub(super) async fn add_server(server_url: Url) {
    let mut server;
    let settings;
    {
        let ldap_ctx = VK_LDAP_CONTEXT.lock().await;
        server = ldap_ctx.new_server(server_url);
        settings = ldap_ctx.get_connection_settings();
    }

    let (pool, res) = VkConnectionPool::new(server.clone(), &settings).await;

    if let Err(err) = res {
        server.set_status(VkLdapServerStatus::UNHEALTHY(err.to_string()));
    }

    VK_LDAP_CONTEXT.lock().await.add_server(server, pool);
}

pub(super) async fn clear_server_list() {
    let pools = VK_LDAP_CONTEXT.lock().await.clear_server_list();
    tokio::spawn(async move {
        for pool in pools.iter() {
            pool.shutdown().await
        }
    });
}

pub async fn refresh_ldap_settings(settings: VkLdapSettings) {
    VK_LDAP_CONTEXT.lock().await.refresh_ldap_settings(settings);
}

pub async fn refresh_connection_settings(settings: VkConnectionSettings) {
    VK_LDAP_CONTEXT
        .lock()
        .await
        .refresh_connection_settings(settings);

    let servers = VK_LDAP_CONTEXT.lock().await.get_current_servers();

    for server in servers {
        refresh_pool_connections(&server).await
    }
}

pub(super) async fn get_servers_health_status() -> Vec<VkLdapServer> {
    VK_LDAP_CONTEXT.lock().await.get_current_servers()
}

pub(super) async fn get_connection(server: &VkLdapServer) -> Result<VkLdapConnection> {
    let settings = VK_LDAP_CONTEXT.lock().await.get_connection_settings();
    VkLdapConnection::new(&settings, &server).await
}

pub(super) async fn get_pool_connection(server: &VkLdapServer) -> VkLdapPoolConnection {
    let pool = VK_LDAP_CONTEXT.lock().await.get_connection_pool(server);
    pool.take_connection().await
}

pub(super) async fn return_pool_connection(pool_conn: VkLdapPoolConnection) {
    let pool = VK_LDAP_CONTEXT
        .lock()
        .await
        .get_connection_pool(&pool_conn.server);
    pool.return_connection(pool_conn).await
}

pub(super) async fn update_server_status(
    server: &VkLdapServer,
    status: VkLdapServerStatus,
    ping_time: Option<Duration>,
) {
    VK_LDAP_CONTEXT
        .lock()
        .await
        .update_server_status(server, status, ping_time)
}

pub(super) async fn refresh_pool_connections(server: &VkLdapServer) {
    let pool;
    let settings;
    {
        let ldap_ctx = VK_LDAP_CONTEXT.lock().await;
        pool = ldap_ctx.get_connection_pool(server);
        settings = ldap_ctx.get_connection_settings();
    }

    match pool.refresh_connections(&settings).await {
        Ok(_) => update_server_status(server, VkLdapServerStatus::HEALTHY, None).await,
        Err(err) => {
            update_server_status(server, VkLdapServerStatus::UNHEALTHY(err.to_string()), None).await
        }
    }
}

async fn run_ldap_op_with_failover<F>(ldap_op: F) -> Result<()>
where
    F: AsyncFn(&mut VkLdapConnection) -> Result<()>,
{
    loop {
        let server;
        let pool;
        {
            let ldap_ctx = VK_LDAP_CONTEXT.lock().await;
            server = ldap_ctx.find_server()?;
            pool = ldap_ctx.get_connection_pool(&server);
        }

        let mut pool_conn = pool.take_connection().await;

        let op_res = ldap_op(&mut pool_conn.conn).await;

        tokio::spawn(async move { pool.return_connection(pool_conn).await });

        if let Err(err) = &op_res {
            if let VkLdapError::LdapConnectionError(_) = err {
                let err_msg = err.to_string();
                update_server_status(&server, VkLdapServerStatus::UNHEALTHY(err_msg), None).await;

                continue;
            }
        }

        return op_res;
    }
}

pub(super) async fn ldap_bind(username: String, password: String) -> Result<()> {
    let settings = VK_LDAP_CONTEXT.lock().await.get_ldap_settings();

    let prefix = settings.bind_db_prefix;
    let suffix = settings.bind_db_suffix;
    let user_dn = format!("{prefix}{username}{suffix}");

    run_ldap_op_with_failover(async move |conn| {
        conn.bind(user_dn.as_str(), password.as_str()).await
    })
    .await
}

pub(super) async fn ldap_search_and_bind(username: String, password: String) -> Result<()> {
    let settings = VK_LDAP_CONTEXT.lock().await.get_ldap_settings();

    run_ldap_op_with_failover(async move |conn| {
        let search_res = conn.search(&settings, username.as_str()).await;
        match search_res {
            Ok(user_dn) => conn.bind(user_dn.as_str(), password.as_str()).await,
            Err(err) => Err(err),
        }
    })
    .await
}
