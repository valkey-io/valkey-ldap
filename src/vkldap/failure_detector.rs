use lazy_static::lazy_static;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use futures::future;
use log::{debug, error};

use super::context;
use super::errors::VkLdapError;
use super::server::{VkLdapServer, VkLdapServerStatus};
use super::{Result, scheduler};

async fn check_server_health(server: VkLdapServer) {
    if server.is_healthy() {
        let mut pool_conn = context::get_pool_connection(&server).await;

        let now = Instant::now();
        let res = pool_conn.conn.ping().await;
        let ping_time = now.elapsed();

        context::return_pool_connection(pool_conn).await;

        if let Err(err) = res {
            context::update_server_status(
                &server,
                VkLdapServerStatus::UNHEALTHY(err.to_string()),
                None,
            )
            .await;
        } else {
            context::update_server_status(
                &server,
                super::server::VkLdapServerStatus::HEALTHY,
                Some(ping_time),
            )
            .await;
        }
    } else {
        let conn_res = context::get_connection(&server).await;

        match conn_res {
            Ok(mut conn) => {
                let res = conn.ping().await;
                if let Ok(_) = res {
                    context::refresh_pool_connections(&server).await;
                }
            }
            Err(err) => {
                context::update_server_status(
                    &server,
                    VkLdapServerStatus::UNHEALTHY(err.to_string()),
                    None,
                )
                .await;
            }
        }
    }
}

async fn failure_detector_iteration() {
    let servers = context::get_servers_health_status().await;

    let mut futures = Vec::new();

    for server in servers {
        futures.push(check_server_health(server));
    }

    future::join_all(futures).await;
}

struct FailureDetector {
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    stop: AtomicBool,
    interval: AtomicU64,
}

impl FailureDetector {
    fn new() -> FailureDetector {
        FailureDetector {
            thread: Mutex::new(None),
            stop: AtomicBool::new(false),
            interval: AtomicU64::new(1),
        }
    }

    fn start(&self) {
        self.stop.store(false, Ordering::Release);
        let mut thread = self.thread.lock().unwrap();

        *thread = Some(thread::spawn(move || {
            debug!("initiating failure detector thread");

            loop {
                std::thread::sleep(Duration::from_secs(
                    FAILURE_DETECTOR.interval.load(Ordering::Relaxed),
                ));

                if let Err(err) = scheduler::submit_sync_task(failure_detector_iteration()) {
                    error!("failed to run failure detector iteration: {err}");
                }

                if FAILURE_DETECTOR.should_stop() {
                    debug!("exiting failure detector loop");
                    return ();
                }
            }
        }))
    }

    fn shutdown(&self) -> Result<()> {
        self.stop.store(true, Ordering::Release);

        let mut thread = self.thread.lock().unwrap();
        let handler_opt = (*thread).take();

        if let Some(handler) = handler_opt {
            match handler.join() {
                Ok(_) => Ok(()),
                Err(_) => Err(VkLdapError::FailedToStopFailuredDetectorThread),
            }
        } else {
            panic!("failure detector thread should have been initialized");
        }
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

lazy_static! {
    static ref FAILURE_DETECTOR: Arc<FailureDetector> = Arc::new(FailureDetector::new());
}

pub fn start_failure_detector_thread() {
    FAILURE_DETECTOR.start();
}

pub fn shutdown_failure_detector_thread() -> Result<()> {
    FAILURE_DETECTOR.shutdown()
}

pub fn set_failure_detector_interval(interval: u64) {
    FAILURE_DETECTOR.interval.store(interval, Ordering::Relaxed);
}
