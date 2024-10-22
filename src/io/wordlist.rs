use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Wordlist file not found: {0}")]
    FileNotFound(String),

    #[error("Error reading file: {0}")]
    ReadError(String),
}

pub fn read_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<String>, Error> {
    let file_path_ref = file_path.as_ref();
    let file = File::open(file_path_ref).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::FileNotFound(file_path_ref.display().to_string()),
        _ => Error::ReadError(file_path_ref.display().to_string()),
    })?;

    let reader = BufReader::new(file);
    let lines: Result<Vec<_>, _> = reader
        .lines()
        .map(|line| line.map_err(|_| Error::ReadError(file_path_ref.display().to_string())))
        .filter(|line| {
            line.as_ref().map_or(true, |content| {
                !content.trim().is_empty() && content.len() < 64
            })
        })
        .collect();

    lines
}
