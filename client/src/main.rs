use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use rand::Rng;
use clap::Parser;

use shared::InitResp;

#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Args {
    #[arg(long)]
    cfg: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    pub signers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let cfg: Config = serde_json::from_str(&args.cfg.unwrap()).unwrap();
    println!("config: {:?}", cfg);

    let mut sessions = HashMap::new();

    for s in cfg.signers {
        let id = hex::encode(rand::thread_rng().random::<[u8; 32]>());
        let resp = reqwest::get(format!("http://{}/init/{}", s, id))
            .await?
            .json::<HashMap<String, String>>()
            .await?;
        println!("{resp:#?}");

        sessions.insert(id, resp);
    }
    Ok(())
}
