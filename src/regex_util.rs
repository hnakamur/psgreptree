use std::str::FromStr;
pub struct CapturesAdapter<'t> {
    caps: regex::Captures<'t>,
}

impl<'t> CapturesAdapter<'t> {
    pub fn new(caps: regex::Captures<'t>) -> Self {
        Self { caps }
    }

    pub fn int_by_index<F: FromStr>(&self, i: usize) -> Result<F, <F as FromStr>::Err> {
        self.caps.get(i).unwrap().as_str().parse::<F>()
    }

    pub fn str_by_index(&self, i: usize) -> &str {
        self.caps.get(i).unwrap().as_str()
    }

    pub fn int_by_name<F: FromStr>(&self, name: &str) -> Result<F, <F as FromStr>::Err> {
        self.caps.name(name).unwrap().as_str().parse::<F>()
    }

    pub fn string_by_name(&self, name: &str) -> String {
        self.caps.name(name).unwrap().as_str().to_string()
    }
}
