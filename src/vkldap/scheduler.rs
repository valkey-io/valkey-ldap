use std::{
    any::Any,
    sync::{Arc, Condvar, Mutex, RwLock, mpsc},
    thread,
};

use futures::future::BoxFuture;
use lazy_static::lazy_static;
use log::{debug, error};
use tokio::runtime;

use super::{Result, errors::VkLdapError};

lazy_static! {
    static ref SCHEDULER: RwLock<Scheduler> = RwLock::new(Scheduler::new());
    static ref ASYNC_RUNTIME: Arc<runtime::Runtime> = Arc::new(
        runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    );
}

pub trait TaskTrait<R>: Future<Output = R> + 'static + Send {}
impl<R, TT: Future<Output = R> + Send + 'static> TaskTrait<R> for TT {}

pub trait CallbackTrait<T: Send, R>: Fn(Option<T>, R) -> () + 'static + Send {}
impl<T: Send, R, CT: Fn(Option<T>, R) -> () + 'static + Send> CallbackTrait<T, R> for CT {}

async fn coerce_future_output<F, R: 'static>(f: F) -> Box<dyn Any>
where
    F: TaskTrait<R>,
{
    Box::new(f.await)
}

fn downcast_callback_input<C, R, T>(
    c: C,
) -> Box<dyn CallbackTrait<Box<dyn Any + Send>, Box<dyn Any>>>
where
    C: CallbackTrait<T, R>,
    R: 'static,
    T: 'static + Send,
{
    Box::new(
        move |data: Option<Box<dyn Any + Send>>, res: Box<dyn Any>| {
            let r = res.downcast::<R>();
            assert!(r.is_ok());
            if let Ok(r) = r {
                match data {
                    Some(d) => {
                        let d = d.downcast::<T>();
                        assert!(d.is_ok());
                        if let Ok(d) = d {
                            c(Some(*d), *r)
                        }
                    }
                    None => c(None, *r),
                }
            }
        },
    )
}

struct Task {
    task: BoxFuture<'static, Box<dyn Any>>,
    callback: Box<dyn CallbackTrait<Box<dyn Any + Send>, Box<dyn Any>>>,
    data: Option<Box<dyn Any + Send>>,
}

impl Task {
    fn new<F, C, R, T>(task: F, callback: C, data: Option<T>) -> Task
    where
        F: TaskTrait<R>,
        C: CallbackTrait<T, R>,
        R: 'static,
        T: 'static + Send,
    {
        Task {
            task: Box::pin(coerce_future_output(task)),
            callback: downcast_callback_input(callback),
            data: match data {
                Some(data) => Some(Box::new(data)),
                None => None,
            },
        }
    }
}

unsafe impl Send for Task {}

enum Job {
    Shutdown,
    Task(Task),
}

struct SchedulerState {
    thread_handler: thread::JoinHandle<()>,
    job_tx: mpsc::Sender<Job>,
}

struct Scheduler {
    state: Option<SchedulerState>,
}

struct JobSender {
    sender: mpsc::Sender<Job>,
}

impl JobSender {
    fn new(sender: mpsc::Sender<Job>) -> JobSender {
        JobSender { sender }
    }

    fn send(&self, job: Job) -> Result<()> {
        match self.sender.send(job) {
            Ok(_) => Ok(()),
            Err(err) => Err(VkLdapError::FailedToSendJobToScheduler(err.to_string())),
        }
    }
}

impl Scheduler {
    fn new() -> Scheduler {
        Scheduler { state: None }
    }

    fn is_initialized(&self) -> bool {
        self.state.is_some()
    }

    fn initialize(&mut self) {
        let (job_tx, job_rx): (mpsc::Sender<Job>, mpsc::Receiver<Job>) = mpsc::channel();

        let handler = thread::spawn(move || {
            debug!("job scheduler thread started");
            ASYNC_RUNTIME.block_on(async move {
                scheduler_loop(job_rx);
            });
            debug!("job scheduler thread ended");
        });

        self.state = Some(SchedulerState {
            thread_handler: handler,
            job_tx: job_tx,
        });
    }

    fn get_sender(&self) -> JobSender {
        JobSender::new(self.state.as_ref().unwrap().job_tx.clone())
    }

    fn shutdown(&mut self) -> Result<()> {
        let sender = self.get_sender();
        sender.send(Job::Shutdown)?;

        let handler = self.state.take().unwrap().thread_handler;
        match handler.join() {
            Ok(_) => Ok(()),
            Err(_) => {
                error!("the scheduler thread returned an error");
                Err(VkLdapError::FailedToShutdownJobScheduler)
            }
        }
    }
}

fn scheduler_loop(job_rx: mpsc::Receiver<Job>) {
    loop {
        match job_rx.recv() {
            Ok(job) => match job {
                Job::Shutdown => return (),
                Job::Task(task) => {
                    tokio::spawn(async move {
                        let res = task.task.await;
                        (task.callback)(task.data, res);
                    });
                }
            },
            Err(err) => {
                error!("scheduler got an error while waiting for new job: {err}");
            }
        }
    }
}

pub fn start_job_scheduler() {
    SCHEDULER.write().unwrap().initialize();
}

pub fn stop_job_scheduler() -> Result<()> {
    SCHEDULER.write().unwrap().shutdown()
}

pub fn is_scheduler_ready() -> bool {
    SCHEDULER.read().unwrap().is_initialized()
}

struct Notify<T: Send> {
    lock: Mutex<Option<T>>,
    cvar: Condvar,
}

impl<T: Send> Notify<T> {
    fn new() -> Notify<T> {
        Notify {
            lock: Mutex::new(None),
            cvar: Condvar::new(),
        }
    }

    fn notify(&self, res: T) {
        let mut cond = self.lock.lock().unwrap();
        *cond = Some(res);
        self.cvar.notify_one();
    }

    fn wait(&self) -> T {
        let mut cond = self.lock.lock().unwrap();
        while (*cond).is_none() {
            cond = self.cvar.wait(cond).unwrap();
        }
        cond.take().unwrap()
    }
}

pub fn submit_sync_task<F, R>(task: F) -> Result<R>
where
    F: TaskTrait<R>,
    R: 'static + Send,
{
    let notify = Arc::new(Notify::<R>::new());
    let notify2 = Arc::clone(&notify);

    let payload = Task::new::<_, _, _, ()>(
        task,
        move |_, res| {
            notify2.notify(res);
        },
        None,
    );

    SCHEDULER
        .read()
        .unwrap()
        .get_sender()
        .send(Job::Task(payload))?;

    Ok(notify.wait())
}

pub fn submit_async_task<F, C, R, T>(task: F, callback: C, data: T) -> Result<()>
where
    F: TaskTrait<R>,
    C: CallbackTrait<T, R>,
    R: 'static,
    T: 'static + Send,
{
    let payload = Task::new(task, callback, Some(data));

    SCHEDULER
        .read()
        .unwrap()
        .get_sender()
        .send(Job::Task(payload))
}
