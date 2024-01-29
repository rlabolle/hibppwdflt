use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

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

    pub fn find_hash(&mut self, hash: &[u8; 16]) -> io::Result<bool> {
        let prefix = u32::from_le_bytes([hash[2], hash[1], hash[0], 0]);
        let suffix = &hash[3..];
        let (start, end) = self.get_bucket_indexes(prefix)?;
        self.dbfile
            .seek(SeekFrom::Start((1 << 24) * 4 + (start as u64) * 13))?;
        for _n in start..end {
            let mut buf = [0; 13];
            self.dbfile.read_exact(&mut buf)?;
            if buf == suffix {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
