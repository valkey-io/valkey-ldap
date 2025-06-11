use std::ffi::CString;
use strum_macros::AsRefStr;
use valkey_module::raw;

const NOT_INITIALISED_MESSAGE: &str = "Valkey module hasn't been initialised.";

/// [ValkeyLogLevel] is a level of logging which can be used when
/// logging with Redis. See [raw::RedisModule_Log] and the official
/// valkey [reference](https://valkey.io/topics/modules-api-ref/).
#[derive(Clone, Copy, Debug, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ValkeyLogLevel {
    Debug,
    Notice,
    Verbose,
    Warning,
}

impl From<log::Level> for ValkeyLogLevel {
    fn from(value: log::Level) -> Self {
        match value {
            log::Level::Error | log::Level::Warn => Self::Warning,
            log::Level::Info => Self::Notice,
            log::Level::Debug => Self::Verbose,
            log::Level::Trace => Self::Debug,
        }
    }
}

pub(crate) fn log_internal<L: Into<ValkeyLogLevel>>(
    ctx: *mut raw::RedisModuleCtx,
    level: L,
    message: &str,
) {
    if cfg!(test) {
        return;
    }

    let level = CString::new(level.into().as_ref()).unwrap();
    let fmt = CString::new(message).unwrap();
    unsafe {
        raw::RedisModule_Log.expect(NOT_INITIALISED_MESSAGE)(ctx, level.as_ptr(), fmt.as_ptr())
    }
}

/// The [log] crate implementation of logging.
pub mod standard_log_implementation {
    use std::sync::{Mutex, OnceLock};

    use super::*;
    use log::{Metadata, Record, SetLoggerError};
    use valkey_module::Context;

    /// The struct which has an implementation of the [log] crate's
    /// logging interface.
    ///
    /// # Note
    ///
    /// Valkey does not support logging at the [log::Level::Error] level,
    /// so logging at this level will be converted to logging at the
    /// [log::Level::Warn] level under the hood.
    struct ValkeyGlobalLogger {
        context: Mutex<*mut raw::RedisModuleCtx>,
    }

    impl ValkeyGlobalLogger {
        fn new() -> Self {
            Self {
                context: Mutex::new(std::ptr::null_mut()),
            }
        }

        fn init(&self, context: &Context) {
            let mut ctx = self.context.lock().unwrap();
            let detached_ctx =
                unsafe { raw::RedisModule_GetDetachedThreadSafeContext.unwrap()(context.ctx) };
            *ctx = detached_ctx;
        }
    }

    // The pointer of the Global logger can only be changed once during
    // the startup. Once one of the [std::sync::OnceLock] or
    // [std::sync::OnceCell] is stabilised, we can remove these unsafe
    // trait implementations in favour of using the aforementioned safe
    // types.
    unsafe impl Send for ValkeyGlobalLogger {}
    unsafe impl Sync for ValkeyGlobalLogger {}

    /// Sets this logger as a global logger. Use this method to set
    /// up the logger. If this method is never called, the default
    /// logger is used which redirects the logging to the standard
    /// input/output streams.
    ///
    /// # Note
    ///
    /// The logging context is created from the module context passed in
    /// `context`.
    ///
    /// In case this function is invoked before the initialisation, and
    /// so without the valkey module context, no context will be used for
    /// the logging, however, the logger will be set.
    ///
    /// # Example
    ///
    /// This function may be called on a module startup, within the
    /// module initialisation function (specified in the
    /// [crate::redis_module] as the `init` argument, which will be used
    /// for the module initialisation and will be passed to the
    /// [raw::Export_RedisModule_Init] function when loading the
    /// module).
    #[allow(dead_code)]
    pub fn setup_for_context(context: &Context) -> Result<(), SetLoggerError> {
        let logger = logger();
        logger.init(context);
        log::set_logger(logger).map(|()| log::set_max_level(log::LevelFilter::Trace))
    }

    fn logger() -> &'static ValkeyGlobalLogger {
        static LOGGER: OnceLock<ValkeyGlobalLogger> = OnceLock::new();
        LOGGER.get_or_init(|| ValkeyGlobalLogger::new())
    }

    impl log::Log for ValkeyGlobalLogger {
        fn enabled(&self, _: &Metadata) -> bool {
            true
        }

        fn log(&self, record: &Record) {
            if !self.enabled(record.metadata()) {
                return;
            }

            let message = match record.level() {
                log::Level::Debug | log::Level::Trace => {
                    format!(
                        "'{}' {}:{}: {}",
                        record.module_path().unwrap_or_default(),
                        record.file().unwrap_or("Unknown"),
                        record.line().unwrap_or(0),
                        record.args()
                    )
                }
                _ => record.args().to_string(),
            };

            let ctx = self.context.lock().unwrap();
            log_internal(*ctx, record.level(), &message);
        }

        fn flush(&self) {
            // The flushing isn't required for the Valkey logging.
        }
    }
}
