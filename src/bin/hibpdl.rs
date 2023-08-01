use backoff::{future::retry_notify, ExponentialBackoff};
use chrono::{TimeZone, Utc};
use clap::Parser;
use futures::{stream, Stream, StreamExt};
use hex::FromHex;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{header, Client};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Old chdb to update
    #[arg(short, long)]
    from: Option<String>,

    /// Output chdb
    #[arg(short, long)]
    output: String,

    /// Number of parallel download buffers
    #[arg(short, long, default_value_t = 160)]
    parallel: usize,
}

pub struct CompactHashDB {
    dbfile: File,
}

impl CompactHashDB {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<CompactHashDB> {
        let dbfile = File::open(path)?;
        Ok(CompactHashDB { dbfile })
    }

    fn read_le_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0; 4];
        self.dbfile.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_le_i64(&mut self) -> io::Result<i64> {
        let mut buf = [0; 8];
        self.dbfile.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }

    pub fn get_timestamp(&mut self) -> io::Result<i64> {
        self.dbfile.seek(SeekFrom::Start(0))?;
        let ts_pos = self.read_le_u32()?;
        self.dbfile
            .seek(SeekFrom::Start((1 << 24) * 4 + (ts_pos as u64) * 13))?;
        self.read_le_i64()
    }

    fn get_bucket_indexes(&mut self, prefix: u32) -> io::Result<(u32, u32)> {
        self.dbfile.seek(SeekFrom::Start((prefix as u64) * 4))?;
        let mut start = self.read_le_u32()?;
        match prefix {
            0 => {
                start = 0;
            }
            0x00FF_FFFF => {
                self.dbfile.seek(SeekFrom::Start(0))?;
            }
            _ => (),
        }
        let end = self.read_le_u32()?;
        Ok((start, end))
    }

    pub fn get_hashs_suffix(&mut self, prefix: u32) -> io::Result<Vec<[u8; 13]>> {
        let (start, end) = self.get_bucket_indexes(prefix)?;
        self.dbfile
            .seek(SeekFrom::Start((1 << 24) * 4 + (start as u64) * 13))?;
        let hashs: io::Result<Vec<[u8; 13]>> = (start..end)
            .map(|_n| {
                let mut buf = [0; 13];
                self.dbfile.read_exact(&mut buf)?;
                Ok(buf)
            })
            .collect();
        hashs
    }
}

#[derive(Debug)]
enum DownloadResult {
    Cached,
    Text(String),
}

#[derive(Debug)]
enum DownloadError {
    StatusCode(u16),
    ReqwestError(reqwest::Error),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DownloadError::StatusCode(code) => write!(f, "Invalid status code: {}", code),
            DownloadError::ReqwestError(ref e) => write!(f, "Reqwest error: {}", e),
        }
    }
}

impl Error for DownloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            DownloadError::StatusCode(_) => None,
            DownloadError::ReqwestError(ref e) => Some(e),
        }
    }
}

async fn download_range(client: Client, prefix: u32) -> (u32, DownloadResult) {
    let retry_strategy = ExponentialBackoff::default();

    retry_notify(
        retry_strategy,
        || async {
            let url = format!(
                "https://api.pwnedpasswords.com/range/{:05X}?mode=ntlm",
                prefix.clone()
            );
            let resp = client
                .get(url)
                .send()
                .await
                .map_err(DownloadError::ReqwestError)?
                .error_for_status()
                .map_err(DownloadError::ReqwestError)?;
            match resp.status().as_u16() {
                200 => {
                    let text = resp.text().await.map_err(DownloadError::ReqwestError)?;
                    Ok((prefix, DownloadResult::Text(text)))
                }
                304 => Ok((prefix, DownloadResult::Cached)),
                code => Err(DownloadError::StatusCode(code))?,
            }
        },
        |e, _dur| eprintln!("Temporary error (retrying): {}", e),
    )
    .await
    .map_err(|e| {
        eprintln!("Permanent error: {}", e);
        e
    })
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

async fn chdb_to_hash_stream<P: AsRef<Path>>(
    prefix: u32,
    path: P,
) -> impl Stream<Item = (u32, [u8; 13])> {
    let mut chdb = CompactHashDB::open(&path).unwrap();
    stream::iter(0x0..=0xF)
        .map(move |p| {
            let pfx = prefix * 16 + p;
            stream::iter(chdb.get_hashs_suffix(pfx).unwrap()).map(move |h| (pfx, h))
        })
        .flatten()
}

async fn download_hash_stream(
    parallel: usize,
    from: Option<String>,
) -> impl Stream<Item = (u32, [u8; 13])> {
    let mut headers = header::HeaderMap::new();
    if let Some(path) = &from {
        let ts = CompactHashDB::open(path).unwrap().get_timestamp().unwrap();
        headers.insert(
            header::IF_MODIFIED_SINCE,
            header::HeaderValue::from_str(Utc.timestamp_nanos(ts).to_rfc2822().as_str()).unwrap(),
        );
    };
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    stream::iter(0x00000..=0xFFFFF)
        .map(move |prefix| {
            let client = client.clone();
            tokio::spawn(download_range(client, prefix))
        })
        .buffered(parallel)
        .filter_map(move |res| {
            let p = from.clone();
            async move {
                match res {
                    Ok((prefix, DownloadResult::Text(text))) => {
                        Some(text_to_hash_stream(prefix, text).await.boxed())
                    }
                    Ok((prefix, DownloadResult::Cached)) => {
                        Some(chdb_to_hash_stream(prefix, p.unwrap()).await.boxed())
                    }
                    Err(e) => {
                        eprintln!("Got a tokio::JoinError: {}", e);
                        None
                    }
                }
            }
        })
        .flatten()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut outdb = File::create(args.output).unwrap();
    let starttime = Utc::now().timestamp_nanos();
    outdb.seek(SeekFrom::Start((1 << 24) * 4)).unwrap();
    let pb = ProgressBar::new(0x1000000);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {percent}% (ETA: {eta_precise})")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_position(0);
    let mut lastprefix = 0u32;
    let mut count = 0u32;
    let mut idx = Vec::with_capacity(0x1000000);
    idx.push(0);
    let hashs = download_hash_stream(args.parallel, args.from).await;
    hashs
        .for_each(|(prefix, suffix)| {
            while prefix != lastprefix {
                idx.push(count);
                lastprefix += 1;
                if lastprefix % 0xFF == 0 {
                    pb.set_position(lastprefix.into());
                }
            }
            outdb.write_all(&suffix).unwrap();
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
    outdb.write_all(&starttime.to_le_bytes()).unwrap();
    outdb.seek(SeekFrom::Start(0)).unwrap();
    for i in &idx {
        outdb.write_all(&i.to_le_bytes()).unwrap();
    }
    pb.finish_with_message("done");
}

#[tokio::test]
async fn test_downlaod_range() {
    let client = Client::new();
    let prefix = 0x8846F;
    let tail = "7EAEE8FB117AD06BDD830B7586C";
    let (pfx, DownloadResult::Text(txt)) = download_range(client, prefix).await else { panic!("no cache") };
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
    let stream = download_hash_stream(1, None).await;
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
