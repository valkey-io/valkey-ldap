use std::time::Duration;

use url::Url;

#[derive(Clone)]
pub enum VkLdapServerStatus {
    HEALTHY,
    UNHEALTHY(String),
}

impl std::fmt::Display for VkLdapServerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HEALTHY => write!(f, "HEALTHY"),
            Self::UNHEALTHY(msg) => write!(f, "UNHEALTHY: [{msg}]"),
        }
    }
}

impl PartialEq for VkLdapServerStatus {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

#[derive(Clone)]
pub struct VkLdapServer {
    url: Url,
    id: usize,
    status: VkLdapServerStatus,
    ping_time: Option<Duration>,
}

impl VkLdapServer {
    pub(super) fn new(url: Url, id: usize, status: VkLdapServerStatus) -> VkLdapServer {
        VkLdapServer {
            url,
            id,
            status,
            ping_time: None,
        }
    }

    pub(super) fn get_url_ref(&self) -> &Url {
        &self.url
    }

    pub(super) fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_host_string(&self) -> String {
        match self.url.host() {
            Some(host) => host.to_string(),
            None => self.url.to_string(),
        }
    }

    pub(super) fn is_healthy(&self) -> bool {
        self.status == VkLdapServerStatus::HEALTHY
    }

    pub fn get_status(&self) -> VkLdapServerStatus {
        return self.status.clone();
    }

    pub(super) fn set_status(&mut self, status: VkLdapServerStatus) {
        self.status = status
    }

    pub(super) fn set_ping_time(&mut self, ping_time: Option<Duration>) {
        self.ping_time = ping_time
    }

    pub fn get_ping_time(&self) -> Option<Duration> {
        self.ping_time
    }
}
