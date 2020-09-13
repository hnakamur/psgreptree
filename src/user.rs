use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::io::Result;

#[derive(Debug, Clone)]
pub struct UserNameCache(HashMap<Uid, Option<String>>);

impl UserNameCache {
    pub fn new() -> UserNameCache {
        UserNameCache(HashMap::new())
    }

    pub fn get(&mut self, uid: Uid) -> Result<Option<String>> {
        Ok(self
            .0
            .entry(uid)
            .or_insert_with(|| User::from_uid(uid).expect("user").map(|u| u.name))
            .clone())
    }
}
