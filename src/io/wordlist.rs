use std::fs::File;
use std::io::{self, BufRead, BufReader};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WordlistError {
    #[error("Wordlist File not found: {0}")]
    FileNotFound(String),
    
    #[error("Error reading file: {0}")]
    ReadError(String),
}

pub fn read_wordlist(file_path: &str) -> Result<Vec<String>, WordlistError> {
    let file = File::open(file_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            WordlistError::FileNotFound(file_path.to_string())
        } else {
            WordlistError::ReadError(file_path.to_string())
        }
    })?;

    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|_| WordlistError::ReadError(file_path.to_string()))?;
        lines.push(line);
    }

    Ok(lines)
}
