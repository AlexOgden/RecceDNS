use colored::{ColoredString, Colorize};
use std::{fmt::Display, io::Write};

#[derive(PartialEq, Eq)]
pub enum Status {
    Info,
    Question,
    Success,
    Warning,
    Error,
}

impl Status {
    fn symbol(&self) -> ColoredString {
        match self {
            Self::Info => "~".cyan(),
            Self::Question => "?".cyan(),
            Self::Success => "+".green(),
            Self::Warning => "!".yellow(),
            Self::Error => "!".red(),
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

pub fn status(status: &Status, message: &impl Display, add_newline: bool) {
    let prefix = format!("[{status}] ");
    let formatted_message = format!("{prefix}{message}");

    // Determine the output stream and print method
    match status {
        Status::Error => {
            if add_newline {
                eprintln!("{formatted_message}");
            } else {
                eprint!("{formatted_message}");
                let _ = std::io::stderr().flush();
            }
        }
        Status::Question => {
            print!("{formatted_message}");
            let _ = std::io::stdout().flush();
        }
        _ => {
            if add_newline {
                println!("{formatted_message}");
            } else {
                print!("{formatted_message}");
                let _ = std::io::stdout().flush();
            }
        }
    }
}

/// Clears the current line in the terminal
pub fn clear_line() {
    if cfg!(target_os = "windows") {
        // On Windows clear only the current line
        print!("\r\x1b[2K");
    } else {
        // On Linux Clear the previous line
        print!("\x1b[F\x1b[K");
    }
    if let Err(error) = std::io::stdout().flush() {
        status(
            &Status::Error,
            &format!("Failed to flush stdout: {error}"),
            false,
        );
    }
}

#[macro_export]
macro_rules! _log_internal {
    ($status:expr, $message:expr, $newline:expr) => {
        $crate::io::logger::status(&$status, &$message, $newline);
    };
    ($status:expr, $message:expr) => {
        let newline = !matches!($status, $crate::io::logger::Status::Question);
        $crate::io::logger::status(&$status, &$message, newline);
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::_log_internal!($crate::io::logger::Status::Info, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_question {
    // Question defaults to no newline
    ($message:expr) => {
        $crate::_log_internal!($crate::io::logger::Status::Question, $message, false);
    };
    ($message:expr, $newline:expr) => {
        $crate::_log_internal!($crate::io::logger::Status::Question, $message, $newline);
    };
}

#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {
        $crate::_log_internal!($crate::io::logger::Status::Success, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::_log_internal!($crate::io::logger::Status::Warning, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::_log_internal!($crate::io::logger::Status::Error, $($arg)*);
    };
}
