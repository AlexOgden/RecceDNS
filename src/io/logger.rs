use colored::{ColoredString, Colorize};
use std::fmt::Display;

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

    match status {
        Status::Error => {
            eprintln!("{}{}{}", if newline { "\n" } else { "" }, prefix, message);
        }
        Status::Question => {
            print!("{}{}{}", if newline { "\n" } else { "" }, prefix, message);
        }
        _ => {
            println!("{}{}{}", if newline { "\n" } else { "" }, prefix, message);
        }
    }
}

/// Clears the current line in the terminal
pub fn clear_line() {
    print!("\r\x1b[2K");
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
