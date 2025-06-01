use crate::error::{AnyTlsError, Result};
use rand::Rng;
use std::collections::HashMap;
use std::str::FromStr;

pub const CHECK_MARK: i32 = -1;

const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

#[derive(Debug, Clone)]
pub struct PaddingScheme {
    pub raw_scheme: Vec<u8>,
    pub stop: u32,
    pub md5: String,
    scheme: HashMap<String, String>,
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::from_str(DEFAULT_PADDING_SCHEME).unwrap()
    }
}

impl FromStr for PaddingScheme {
    type Err = AnyTlsError;

    fn from_str(s: &str) -> Result<Self> {
        let raw_scheme = s.as_bytes().to_vec();
        let md5 = format!("{:x}", md5::compute(&raw_scheme));
        
        let mut scheme = HashMap::new();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            
            if let Some((key, value)) = line.split_once('=') {
                scheme.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        
        let stop = scheme.get("stop")
            .ok_or_else(|| AnyTlsError::InvalidPaddingScheme)?
            .parse::<u32>()
            .map_err(|_| AnyTlsError::InvalidPaddingScheme)?;
        
        Ok(Self {
            raw_scheme,
            stop,
            md5,
            scheme,
        })
    }
}

impl PaddingScheme {
    /// Generate record payload sizes for a given packet number
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let mut pkt_sizes = Vec::new();
        
        if let Some(s) = self.scheme.get(&pkt.to_string()) {
            let s_ranges: Vec<&str> = s.split(',').collect();
            
            for s_range in s_ranges {
                let s_range = s_range.trim();
                
                if s_range == "c" {
                    pkt_sizes.push(CHECK_MARK);
                    continue;
                }
                
                if let Some((min_str, max_str)) = s_range.split_once('-') {
                    if let (Ok(min), Ok(max)) = (min_str.parse::<i64>(), max_str.parse::<i64>()) {
                        let (min, max) = (min.min(max), min.max(max));
                        
                        if min <= 0 || max <= 0 {
                            continue;
                        }
                        
                        if min == max {
                            pkt_sizes.push(min as i32);
                        } else {
                            let mut rng = rand::thread_rng();
                            let value = rng.gen_range(min..=max);
                            pkt_sizes.push(value as i32);
                        }
                    }
                }
            }
        }
        
        pkt_sizes
    }
} 