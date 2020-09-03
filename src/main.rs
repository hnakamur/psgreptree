fn main() {
    std::env::set_var("SMOL_THREADS", format!("{}", num_cpus::get()));

    let task = smol::spawn(async { 1 + 2 });

    smol::block_on(async {
        println!("{}", task.await);
    });
}
