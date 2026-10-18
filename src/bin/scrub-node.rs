#[tokio::main(worker_threads = 2)]
async fn main() {
    if let Err(e) = pathfinder::node::run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
