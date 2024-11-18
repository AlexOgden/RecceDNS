use rand::Rng;
use std::str::FromStr;

#[derive(Debug)]
pub enum Delay {
    Single(u64),
    Range(u64, u64),
}

impl Delay {
    pub fn get_delay(&self) -> u64 {
        match self {
            Self::Single(value) => *value,
            Self::Range(min, max) => {
                let mut rng = rand::thread_rng();
                rng.gen_range(*min..=*max)
            }
        }
    }
}

impl FromStr for Delay {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((min, max)) = s.split_once('-') {
            let min = min.parse::<u64>().map_err(|_| "Invalid number in range")?;
            let max = max.parse::<u64>().map_err(|_| "Invalid number in range")?;
            if min > max {
                return Err("Invalid range: min is greater than max".into());
            }
            Ok(Self::Range(min, max))
        } else {
            let value = s.parse::<u64>().map_err(|_| "Invalid number")?;
            Ok(Self::Single(value))
        }
    }
}
