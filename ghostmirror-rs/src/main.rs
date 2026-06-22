use clap::{Parser, Subcommand};
use ghostmirror_rs::banner_grabber;
use ghostmirror_rs::http_fingerprint;
use ghostmirror_rs::output;
use ghostmirror_rs::port_scanner;

#[derive(Parser)]
#[command(name = "ghostmirror-rs", about = "GhostMirror Native Rust Engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Portscan {
        #[arg(long)]
        host: String,
        #[arg(long)]
        ports: String,
        #[arg(long, default_value = "3")]
        timeout: u64,
    },
    Banner {
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "80")]
        port: u16,
        #[arg(long)]
        tls: bool,
    },
    Fingerprint {
        #[arg(long)]
        url: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Portscan {
            host,
            ports,
            timeout,
        } => match port_scanner::scan(&host, &ports, timeout) {
            Ok(result) => output::print_json(&result),
            Err(e) => {
                eprintln!("{{\"error\":\"{}\"}}", e);
                std::process::exit(1);
            }
        },
        Commands::Banner { host, port, tls } => match banner_grabber::grab(&host, port, tls) {
            Ok(result) => output::print_json(&result),
            Err(e) => {
                eprintln!("{{\"error\":\"{}\"}}", e);
                std::process::exit(1);
            }
        },
        Commands::Fingerprint { url } => match http_fingerprint::fingerprint(&url) {
            Ok(result) => output::print_json(&result),
            Err(e) => {
                eprintln!("{{\"error\":\"{}\"}}", e);
                std::process::exit(1);
            }
        },
    }
}
