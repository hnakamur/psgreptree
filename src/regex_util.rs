use std::str::FromStr;
pub struct CapturesAdapter<'t> {
    caps: regex::Captures<'t>,
}

impl<'t> CapturesAdapter<'t> {
    pub fn new(caps: regex::Captures<'t>) -> Self {
        Self { caps }
    }

    pub fn string_by_name(&self, name: &str) -> String {
        self.caps.name(name).unwrap().as_str().to_string()
    }

    pub fn int_by_name<F: FromStr>(&self, name: &str) -> Result<F, <F as FromStr>::Err> {
        self.caps.name(name).unwrap().as_str().parse::<F>()
    }
}
