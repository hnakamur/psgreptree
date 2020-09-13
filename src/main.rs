#[macro_use]
extern crate lazy_static;

use clap::{App, Arg};

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
                .index(1),
        )
        .get_matches();
    let pattern = matches.value_of("PATTERN");

    std::env::set_var("SMOL_THREADS", format!("{}", num_cpus::get()));

    let proc_forest = smol::block_on(async { proc::ProcessForest::new(pattern.unwrap()).await });
    print!("{}", proc_forest);
}
