use sv1_proxy::{run_proxy, run_wallet, WalletMessageChannel};
use tokio::runtime::Runtime;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    let args: Vec<String> = std::env::args().collect();
    let upstream_addr = args.get(1).expect("Missing upstream address argument").clone();
    let worker_name   = args.get(2).expect("Missing worker name argument").clone();

    let on_new_block = Arc::new(|block_msg: String| {
        println!("(Callback) A new block arrived: {}", block_msg);
        // Possibly do more interesting things here
    });

    let on_share_submitted = Arc::new(|share_msg: String| {
        println!("(Callback) Miner submitted a share: {}", share_msg);
        // Possibly do more interesting things here
    });

    rt.block_on(async {
        let (tx_to_wallet, rx_to_wallet) = mpsc::channel(100);
        let (tx_from_wallet, rx_from_wallet) = mpsc::channel(100);

        let proxy_future = run_proxy(
            &upstream_addr,
            &worker_name,
            on_new_block,
            on_share_submitted,
            tx_to_wallet,
            rx_from_wallet,
        );

        let wallet_future = run_wallet(rx_to_wallet, tx_from_wallet);

        select! {
            result = proxy_future => result,
            result = wallet_future => result,
        }
    })
}
