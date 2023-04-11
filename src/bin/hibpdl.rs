use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::{stream, Stream, StreamExt};
use hex::FromHex;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;

use chrono::{TimeZone, Utc};
use reqwest::header::IF_MODIFIED_SINCE;

const PARALLEL_REQUESTS: usize = 20 * 8;

async fn download_range(client: Client, prefix: u32) -> (u32, String) {
    retry(ExponentialBackoff::default(), || async {
        let url = format!(
            "https://api.pwnedpasswords.com/range/{:05X}?mode=ntlm",
            prefix.clone()
        );
        let resp = client.get(url).send().await.map_err(|e| {
            eprintln!("Got a reqwest::Error: {}", e);
            e
        })?;
        let text = resp.text().await.map_err(|e| {
            eprintln!("Got a reqwest::Error: {}", e);
            e
        })?;
        Ok((prefix, text))
    })
    .await
    .unwrap()
}

async fn text_to_hash_stream(prefix: u32, text: String) -> impl Stream<Item = (u32, [u8; 13])> {
    stream::iter(
        text.lines()
            .filter_map(move |line| {
                if line.len() >= 27 {
                    match u32::from_str_radix(&line[..1], 16) {
                        Ok(digit) => {
                            let prefix = prefix * 16 + digit;
                            match <[u8; 13]>::from_hex(&line[1..27]) {
                                Ok(suffix) => Some((prefix, suffix)),
                                Err(e) => {
                                    eprintln!(
                                        "Cannot decode suffix '{}' from hex: {}",
                                        &line[1..27],
                                        e
                                    );
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Invalid first char '{}': {}", &line[..1], e);
                            None
                        }
                    }
                } else {
                    eprintln!("Line too short");
                    None
                }
            })
            .collect::<Vec<_>>(),
    )
}

async fn download_hash_stream(parallel: usize) -> impl Stream<Item = (u32, [u8; 13])> {
    let client = Client::new();
    stream::iter(0x00000..=0xFFFFF)
        .map(move |prefix| {
            let client = client.clone();
            tokio::spawn(download_range(client, prefix))
        })
        .buffered(parallel)
        .filter_map(|res| async {
            match res {
                Ok((prefix, text)) => Some(text_to_hash_stream(prefix, text).await),
                Err(e) => {
                    eprintln!("Got a tokio::JoinError: {}", e);
                    None
                }
            }
        })
        .flatten()
}

#[tokio::main]
async fn main() {
    let pb = ProgressBar::new(0x1000000);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {percent}% (ETA: {eta_precise})")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_position(0);
    let mut lastprefix = 0u32;
    let mut count = 0u32;
    let mut idx = Vec::with_capacity(0x1000000);
    idx.push(0);
    let hashs = download_hash_stream(PARALLEL_REQUESTS).await;
    hashs
        .for_each(|(prefix, suffix)| {
            while prefix != lastprefix {
                idx.push(count);
                lastprefix += 1;
                if lastprefix % 0xFF == 0 {
                    pb.set_position(lastprefix.into());
                }
            }
            let _hash = format!("{:06X}{}", prefix, hex::encode_upper(suffix));
            count += 1;
            futures::future::ready(())
        })
        .await;
    while lastprefix != 0xFFFFFF {
        idx.push(count);
        lastprefix += 1;
        pb.set_position(lastprefix.into());
    }
    idx[0] = count;
    pb.finish_with_message("done");
    println!("{:?}", idx.len());
}

#[tokio::test]
async fn test_downlaod_range() {
    let client = Client::new();
    let prefix = 0x8846F;
    let tail = "7EAEE8FB117AD06BDD830B7586C";
    let (pfx, txt) = download_range(client, prefix).await;
    assert_eq!(prefix, pfx);
    assert!(txt.contains(tail));
}

#[tokio::test]
async fn test_text_to_hash_stream() {
    let prefix = 0x00000;
    let text = "\
001F4A473ED6959F04464F91BB5:4
0034C209E9CA85D03512759C405:3
00CEB20FBC9D76790D7F9E6E22B:1
00F23B59311F4FFB01D6D620487:4
011059407D743D40689940F858C:1
0113BDEB707C98A8234826BF788:6
0128830292D92FA6B226EEC986B:4
015B1284879951DC072C80735DC:4
01991F12B30E3B00E7CCED2ADFB:3
01FE8FBE6BE79FC5A0D39CDFD68:5";
    let stream = text_to_hash_stream(prefix, text.to_string()).await;
    let result = stream.collect::<Vec<_>>().await;
    assert_eq!(
        result,
        vec![
            (
                0,
                [0x01, 0xF4, 0xA4, 0x73, 0xED, 0x69, 0x59, 0xF0, 0x44, 0x64, 0xF9, 0x1B, 0xB5]
            ),
            (
                0,
                [0x03, 0x4C, 0x20, 0x9E, 0x9C, 0xA8, 0x5D, 0x03, 0x51, 0x27, 0x59, 0xC4, 0x05]
            ),
            (
                0,
                [0x0C, 0xEB, 0x20, 0xFB, 0xC9, 0xD7, 0x67, 0x90, 0xD7, 0xF9, 0xE6, 0xE2, 0x2B]
            ),
            (
                0,
                [0x0F, 0x23, 0xB5, 0x93, 0x11, 0xF4, 0xFF, 0xB0, 0x1D, 0x6D, 0x62, 0x04, 0x87]
            ),
            (
                0,
                [0x11, 0x05, 0x94, 0x07, 0xD7, 0x43, 0xD4, 0x06, 0x89, 0x94, 0x0F, 0x85, 0x8C]
            ),
            (
                0,
                [0x11, 0x3B, 0xDE, 0xB7, 0x07, 0xC9, 0x8A, 0x82, 0x34, 0x82, 0x6B, 0xF7, 0x88]
            ),
            (
                0,
                [0x12, 0x88, 0x30, 0x29, 0x2D, 0x92, 0xFA, 0x6B, 0x22, 0x6E, 0xEC, 0x98, 0x6B]
            ),
            (
                0,
                [0x15, 0xB1, 0x28, 0x48, 0x79, 0x95, 0x1D, 0xC0, 0x72, 0xC8, 0x07, 0x35, 0xDC]
            ),
            (
                0,
                [0x19, 0x91, 0xF1, 0x2B, 0x30, 0xE3, 0xB0, 0x0E, 0x7C, 0xCE, 0xD2, 0xAD, 0xFB]
            ),
            (
                0,
                [0x1F, 0xE8, 0xFB, 0xE6, 0xBE, 0x79, 0xFC, 0x5A, 0x0D, 0x39, 0xCD, 0xFD, 0x68]
            )
        ]
    );
}

#[tokio::test]
async fn test_download_hash_stream() {
    let stream = download_hash_stream(1).await;
    let result = stream.take(10).collect::<Vec<_>>().await;
    assert_eq!(
        result,
        vec![
            (
                0,
                [0x01, 0xF4, 0xA4, 0x73, 0xED, 0x69, 0x59, 0xF0, 0x44, 0x64, 0xF9, 0x1B, 0xB5]
            ),
            (
                0,
                [0x03, 0x4C, 0x20, 0x9E, 0x9C, 0xA8, 0x5D, 0x03, 0x51, 0x27, 0x59, 0xC4, 0x05]
            ),
            (
                0,
                [0x0C, 0xEB, 0x20, 0xFB, 0xC9, 0xD7, 0x67, 0x90, 0xD7, 0xF9, 0xE6, 0xE2, 0x2B]
            ),
            (
                0,
                [0x0F, 0x23, 0xB5, 0x93, 0x11, 0xF4, 0xFF, 0xB0, 0x1D, 0x6D, 0x62, 0x04, 0x87]
            ),
            (
                0,
                [0x11, 0x05, 0x94, 0x07, 0xD7, 0x43, 0xD4, 0x06, 0x89, 0x94, 0x0F, 0x85, 0x8C]
            ),
            (
                0,
                [0x11, 0x3B, 0xDE, 0xB7, 0x07, 0xC9, 0x8A, 0x82, 0x34, 0x82, 0x6B, 0xF7, 0x88]
            ),
            (
                0,
                [0x12, 0x88, 0x30, 0x29, 0x2D, 0x92, 0xFA, 0x6B, 0x22, 0x6E, 0xEC, 0x98, 0x6B]
            ),
            (
                0,
                [0x15, 0xB1, 0x28, 0x48, 0x79, 0x95, 0x1D, 0xC0, 0x72, 0xC8, 0x07, 0x35, 0xDC]
            ),
            (
                0,
                [0x19, 0x91, 0xF1, 0x2B, 0x30, 0xE3, 0xB0, 0x0E, 0x7C, 0xCE, 0xD2, 0xAD, 0xFB]
            ),
            (
                0,
                [0x1F, 0xE8, 0xFB, 0xE6, 0xBE, 0x79, 0xFC, 0x5A, 0x0D, 0x39, 0xCD, 0xFD, 0x68]
            )
        ]
    );
}
