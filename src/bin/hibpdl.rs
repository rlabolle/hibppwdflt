use futures::{stream, StreamExt};
use tokio;
use reqwest::Client;
use backoff::ExponentialBackoff;
use backoff::future::retry;


const PARALLEL_REQUESTS: usize = 20*8;

#[tokio::main]
async fn main() {
    let client = Client::new();

    let bodies = stream::iter(0x00000..=0xFFFFF)
        .map(|prefix| {
            let client = client.clone();
            tokio::spawn(async move {
                retry(ExponentialBackoff::default(), || async {
                    let url = format!("https://api.pwnedpasswords.com/range/{prefix:05X}?mode=ntlm");
                    let resp = client.get(url).send().await.map_err(|e| { eprintln!("Got a reqwest::Error: {}", e); e })?;
                    let text = resp.text().await.map_err(|e| { eprintln!("Got a reqwest::Error: {}", e); e })?;
                    Ok((prefix, text))
                }).await.unwrap()
            })
        })
        .buffered(PARALLEL_REQUESTS)
        .filter_map(|res| async {
            match res {
                Ok((prefix, text)) => Some(stream::iter(text.lines().map(String::from).collect::<Vec<String>>()).map(move |line| (prefix,line))),
                Err(e) => { eprintln!("Got a tokio::JoinError: {}", e); None },
            }
        }).flatten();

    bodies
        .for_each(|(prefix,line)| async move {
            println!("{prefix:05X}{line:.27}")
        })
        .await;
}
