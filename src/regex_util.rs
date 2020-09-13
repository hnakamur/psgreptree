use anyhow::{Context, Result};
use regex::Captures;
use std::error::Error;
use std::str::FromStr;

pub struct CapturesAdapter<'t> {
    caps: Captures<'t>,
}

impl<'t> CapturesAdapter<'t> {
    pub fn new(caps: Captures<'t>) -> Self {
        Self { caps }
    }

    pub fn int_by_index<F: FromStr>(&self, i: usize) -> Result<F>
    where
        <F as FromStr>::Err: Error + Send + Sync + 'static,
    {
        let s = self.str_by_index(i);
        s.parse::<F>()
            .with_context(|| format!("cannot parse match indexed {} (value: {})", i, s))
    }

    pub fn str_by_index(&self, i: usize) -> &str {
        match self.caps.get(i) {
            Some(m) => m.as_str(),
            None => panic!(format!("regex match index {} is out of bounds", i)),
        }
    }

    pub fn int_by_name<F: FromStr>(&self, name: &str) -> Result<F>
    where
        <F as FromStr>::Err: Error + Send + Sync + 'static,
    {
        let s = self.str_by_name(name);
        s.parse::<F>()
            .with_context(|| format!("cannot parse match named {} (value: {})", name, s))
    }

    pub fn string_by_name(&self, name: &str) -> String {
        self.str_by_name(name).to_string()
    }

    pub fn str_by_name(&self, name: &str) -> &str {
        match self.caps.name(name) {
            Some(m) => m.as_str(),
            None => panic!(format!("regex match name {} not found in captures", name)),
        }
    }
}
