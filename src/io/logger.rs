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

pub fn status(status: &Status, message: &impl Display, newline: bool) {
    let clear_line = "\r\x1b[2K";
    let prefix = format!("{clear_line}[{status}] ");
    let newline_str = if newline { "\n" } else { "" };
    let formatted_message = format!("{newline_str}{prefix}{message}");

    match status {
        Status::Error => eprintln!("{formatted_message}"),
        Status::Question => print!("{formatted_message}"),
        _ => println!("{formatted_message}"),
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
macro_rules! log_info {
    ($message:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Info,
            &$message.to_string(),
            false,
        );
    };
    ($message:expr, $newline:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Info,
            &$message.to_string(),
            $newline,
        );
    };
}

#[macro_export]
macro_rules! log_question {
    ($message:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Question,
            &$message.to_string(),
            false,
        );
    };
    ($message:expr, $newline:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Question,
            &$message.to_string(),
            $newline,
        );
    };
}

#[macro_export]
macro_rules! log_success {
    ($message:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Success,
            &$message.to_string(),
            false,
        );
    };
    ($message:expr, $newline:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Success,
            &$message.to_string(),
            $newline,
        );
    };
}

#[macro_export]
macro_rules! log_warn {
    ($message:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Warning,
            &$message.to_string(),
            false,
        );
    };
    ($message:expr, $newline:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Warning,
            &$message.to_string(),
            $newline,
        );
    };
}

#[macro_export]
macro_rules! log_error {
    ($message:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Error,
            &$message.to_string(),
            false,
        );
    };
    ($message:expr, $newline:expr) => {
        $crate::io::logger::status(
            &$crate::io::logger::Status::Error,
            &$message.to_string(),
            $newline,
        );
    };
}
