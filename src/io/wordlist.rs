use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Wordlist file not found: {0}")]
    FileNotFound(String),

    #[error("Error reading file: {0}")]
    ReadError(String),
}

pub struct WordlistStream {
    lines: io::Lines<BufReader<File>>,
    file_path: String,
}

impl Iterator for WordlistStream {
    type Item = Result<String, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line_result = self.lines.next()?;
            match line_result {
                Ok(line) => {
                    let sanitized = line.trim_matches(|c: char| c == '\r' || c == '\n').trim();
                    if !sanitized.is_empty() && sanitized.len() < 64 {
                        return Some(Ok(sanitized.to_string()));
                    }
                }
                Err(_) => {
                    return Some(Err(Error::ReadError(self.file_path.clone())));
                }
            }
        }
    }
}

/// Open a wordlist for streaming without loading the entire file into memory.
pub fn stream_subdomain_list<P: AsRef<Path>>(file_path: P) -> Result<WordlistStream, Error> {
    let file_path_ref = file_path.as_ref();
    let file = File::open(file_path_ref).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::FileNotFound(file_path_ref.display().to_string()),
        _ => Error::ReadError(file_path_ref.display().to_string()),
    })?;

    let reader = BufReader::with_capacity(64 * 1024, file);
    Ok(WordlistStream {
        lines: reader.lines(),
        file_path: file_path_ref.display().to_string(),
    })
}

/// Read all subdomains from a wordlist into a Vec, sanitizing whitespace and CRLF line endings.
pub fn read_subdomain_list<P: AsRef<Path>>(file_path: P) -> Result<Vec<String>, Error> {
    stream_subdomain_list(file_path)?.collect()
}

/// Fast line counter using an 8KB buffer without allocating strings.
pub fn count_lines<P: AsRef<Path>>(file_path: P) -> Result<u64, Error> {
    let file_path_ref = file_path.as_ref();
    let mut file = File::open(file_path_ref).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::FileNotFound(file_path_ref.display().to_string()),
        _ => Error::ReadError(file_path_ref.display().to_string()),
    })?;

    let mut buf = [0u8; 8 * 1024];
    let mut count = 0u64;
    let mut last_byte = b'\n';
    let mut total_bytes = 0usize;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| Error::ReadError(file_path_ref.display().to_string()))?;
        if n == 0 {
            break;
        }
        total_bytes += n;
        for &b in &buf[..n] {
            if b == b'\n' {
                count += 1;
            }
        }
        last_byte = buf[n - 1];
    }
    if total_bytes > 0 && last_byte != b'\n' {
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_sanitizes_crlf_and_whitespace() {
        let dir = std::env::temp_dir();
        let test_file = dir.join("test_reccedns_wordlist_crlf.txt");
        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(b"admin\r\napi\r\n\r\n  portal  \r\n").unwrap();
            // A line > 63 chars that should be filtered out
            f.write_all(b"a".repeat(64).as_slice()).unwrap();
            f.write_all(b"\r\nwww\n").unwrap();
        }

        let words = read_subdomain_list(&test_file).unwrap();
        assert_eq!(words, vec!["admin", "api", "portal", "www"]);

        let count = count_lines(&test_file).unwrap();
        assert!(count >= 4);

        let _ = std::fs::remove_file(test_file);
    }

    #[test]
    fn test_count_lines_single_line_no_newline() {
        let dir = std::env::temp_dir();
        let test_file = dir.join(format!(
            "test_reccedns_count_lines_single_{}.txt",
            rand::random::<u64>()
        ));
        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(b"admin").unwrap();
        }

        let count = count_lines(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_lines_empty_file() {
        let dir = std::env::temp_dir();
        let test_file = dir.join(format!(
            "test_reccedns_count_lines_empty_{}.txt",
            rand::random::<u64>()
        ));
        {
            let _f = File::create(&test_file).unwrap();
        }

        let count = count_lines(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(count, 0);
    }
}
