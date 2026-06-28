use anyhow::Result;
use std::fs::File;
use std::io::{self, BufRead};

#[derive(Debug, Clone)]
pub struct MutationEngine {
    rules: Vec<String>,
    words: Vec<String>,
}

impl MutationEngine {
    pub fn new(rules_path: Option<&String>, words_path: Option<&String>) -> Result<Self> {
        let mut rules = Vec::new();
        if let Some(path) = rules_path {
            let file = File::open(path)?;
            for line in io::BufReader::new(file).lines() {
                let l = line?;
                let l = l.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    rules.push(l.to_string());
                }
            }
        } else {
            // Default rules if only words are provided
            rules.push("[sub]-[word]".to_string());
            rules.push("[word]-[sub]".to_string());
            rules.push("[sub][word]".to_string());
            rules.push("[word][sub]".to_string());
        }

        let mut words = Vec::new();
        if let Some(path) = words_path {
            let file = File::open(path)?;
            for line in io::BufReader::new(file).lines() {
                let l = line?;
                let l = l.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    words.push(l.to_string());
                }
            }
        } else {
            // Default words if only rules are provided and they contain [word]
            words.push("dev".to_string());
            words.push("staging".to_string());
            words.push("prod".to_string());
            words.push("test".to_string());
            words.push("api".to_string());
            words.push("v1".to_string());
            words.push("v2".to_string());
        }

        Ok(Self { rules, words })
    }

    /// Mutates a base subdomain, returning a list of permutations.
    pub fn mutate(&self, base: &str) -> Vec<String> {
        let mut results = Vec::new();

        for rule in &self.rules {
            if rule.contains("[word]") {
                for word in &self.words {
                    let mutated = rule.replace("[sub]", base).replace("[word]", word);
                    results.push(mutated);
                }
            } else {
                let mutated = rule.replace("[sub]", base);
                results.push(mutated);
            }
        }

        results
    }
}
