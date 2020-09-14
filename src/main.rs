#[macro_use]
extern crate lazy_static;

use clap::{App, Arg};
use regex::Regex;

mod proc;
mod regex_util;
mod tty;
mod user;

fn main() {
    let matches = App::new("psgreptree")
        .version("0.1.0")
        .author("Hiroaki Nakamura <hnakamur@gmail.com>")
        .about("show process tree filtered by pattern match for command lines")
        .arg(
            Arg::with_name("PATTERN")
                .value_name("pattern")
                .help("Sets a regular expression to match process command lines")
                .default_value(".*")
                .index(1)
                .required(true)
                .validator(|val| match Regex::new(&val) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from(
                        "The first argument must be a valid regular expression",
                    )),
                }),
        )
        .get_matches();
    let pattern = matches.value_of("PATTERN").unwrap();
    let re = Regex::new(pattern).expect("valid regular expression");

    std::env::set_var("SMOL_THREADS", format!("{}", num_cpus::get()));

    match smol::block_on(async { proc::ProcessForest::new(&re).await }) {
        Ok(proc_forest) => print!("{}", proc_forest),
        Err(e) => eprintln!("Error {}", e),
    }
}
