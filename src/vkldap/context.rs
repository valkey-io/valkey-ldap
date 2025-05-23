use lazy_static::lazy_static;
use std::{
    sync::Mutex,
    thread::{self, JoinHandle},
};

use log::{debug, info};
use url::Url;

use super::{
    Result,
    errors::VkLdapError,
    failure_detector,
    server::{VkLdapServer, VkLdapServerStatus},
    settings::VkLdapSettings,
};

pub(super) struct VkLdapContext {
    servers: Vec<VkLdapServer>,
    stop_failure_detector: bool,
    detector_thread_handle: Option<thread::JoinHandle<()>>,
    settings: VkLdapSettings,
}

impl VkLdapContext {
    fn new() -> VkLdapContext {
        VkLdapContext {
            servers: Vec::new(),
            stop_failure_detector: false,
            detector_thread_handle: None,
            settings: VkLdapSettings::default(),
        }
    }

    pub fn should_stop_failure_detector_thread(&self) -> bool {
        self.stop_failure_detector
    }

    pub fn stop_failure_detector_thread(&mut self) -> Result<()> {
        let handler_opt: Option<JoinHandle<()>>;
        {
            self.stop_failure_detector = true;
            handler_opt = self.detector_thread_handle.take();
        }

        if let Some(handler) = handler_opt {
            match handler.join() {
                Ok(_) => Ok(()),
                Err(_) => Err(VkLdapError::FailedToStopFailuredDetectorThread),
            }
        } else {
            panic!("failure detector thread should have been initialized");
        }
    }

    pub fn start_ldap_failure_detector(&mut self) -> () {
        self.detector_thread_handle = Some(thread::spawn(|| {
            debug!("initiating failure detector thread");
            failure_detector::failure_detector_loop();
            debug!("shutting down failure detector thread");
        }));
    }

    pub fn get_settings_copy(&self) -> VkLdapSettings {
        self.settings.clone()
    }

    pub fn refresh_settings(&mut self, settings: VkLdapSettings) {
        self.settings = settings
    }

    pub fn clear_server_list(&mut self) -> () {
        self.servers.clear();
    }

    pub fn add_server(&mut self, server_url: Url) -> () {
        self.servers.push(VkLdapServer::new(
            server_url,
            self.servers.len(),
            VkLdapServerStatus::HEALTHY,
        ));
    }

    pub fn get_current_servers(&self) -> Vec<VkLdapServer> {
        let mut res: Vec<VkLdapServer> = Vec::new();
        self.servers.iter().for_each(|s| res.push(s.clone()));
        res
    }

    pub fn update_server_status(&mut self, server: VkLdapServer, status: VkLdapServerStatus) {
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
        }
    }

    pub fn find_server(&self) -> Result<VkLdapServer> {
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

    pub fn failover_server(
        &mut self,
        failed_server: VkLdapServer,
        err: &VkLdapError,
    ) -> Result<VkLdapServer> {
        if self.servers.is_empty() {
            // The server list was cleared in the meantime, no new server can be returned.
            return Err(VkLdapError::NoServerConfigured);
        }
        let next_server_index = (failed_server.get_id() + 1) % self.servers.len();

        if self.servers[failed_server.get_id()].is_healthy() {
            if self.servers[failed_server.get_id()].get_url_ref() == failed_server.get_url_ref() {
                // Mark the server unhealthy with the last error raised by the LDAP connection.
                let url = failed_server.get_url_ref();
                let err_msg = err.to_string();
                info!("transition server {url} HEALTHY -> UNHEALTHY: {err_msg}");
                self.servers[failed_server.get_id()]
                    .set_status(VkLdapServerStatus::UNHEALTHY(err_msg));
            }
        }

        for idx in next_server_index..self.servers.len() {
            let new_server = &self.servers[idx];
            if new_server.is_healthy() {
                return Ok(new_server.clone());
            }
        }

        Err(VkLdapError::NoHealthyServerAvailable)
    }
}

lazy_static! {
    pub(super) static ref VK_LDAP_CONTEXT: Mutex<VkLdapContext> = Mutex::new(VkLdapContext::new());
}
