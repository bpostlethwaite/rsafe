use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use blake2::{digest::consts::U32, Blake2b, Digest};
use ngrammatic::{CorpusBuilder, Pad};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::vec::Vec;

type Blake2b256 = Blake2b<U32>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Record {
    pub account: String,
    pub username: String,
    pub password: String,
    pub extra: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Records(pub Vec<Record>);

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:20} {:20} {:20} {}",
            self.account,
            self.username,
            self.password,
            self.extra.clone().unwrap_or("".to_owned())
        )
    }
}

impl fmt::Display for Records {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.iter().fold(Ok(()), |result, record| {
            result.and_then(|_| writeln!(f, "{}", record))
        })
    }
}

pub fn encrypt(bkey: &[u8], bnonce: &[u8], records: Vec<Record>) -> Result<Vec<u8>> {
    let mut hasher = Blake2b256::new();
    hasher.update(bkey);
    let hkey = hasher.finalize();

    let key = Key::from_slice(&hkey);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(bnonce); // unique per message

    let mut wtr = csv::Writer::from_writer(vec![]);
    for record in records {
        wtr.serialize(record)?;
    }

    let unlocked_safe: Vec<u8> = wtr.into_inner()?;
    let locked_safe = cipher
        .encrypt(nonce, unlocked_safe.as_ref())
        .map_err(|e| anyhow!("decrypt error: {}", e))?;

    Ok(locked_safe)
}

pub fn decrypt(bkey: &[u8], bnonce: &[u8], locked_safe: &[u8]) -> Result<Vec<Record>> {
    if locked_safe.len() == 0 {
        return Ok(vec![]);
    }

    let mut hasher = Blake2b256::new();
    hasher.update(bkey);
    let hkey = hasher.finalize();

    let key = Key::from_slice(&hkey);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(bnonce); // unique per message
    let unlocked_safe = cipher
        .decrypt(nonce, locked_safe.as_ref())
        .map_err(|e| anyhow!("decrypt error: {}", e))?;

    let mut rdr = csv::Reader::from_reader(&*unlocked_safe);
    let records: Vec<Record> = rdr.deserialize().filter_map(|r| r.ok()).collect();

    Ok(records)
}

pub fn put_record(
    bkey: &[u8],
    bnonce: &[u8],
    locked_safe: &[u8],
    record: Record,
) -> Result<Vec<u8>> {
    let mut records = decrypt(bkey, bnonce, locked_safe)?;

    match records.iter().position(|r| r.account == record.account) {
        Some(i) => records[i] = record,
        None => records.push(record),
    };

    return encrypt(bkey, bnonce, records);
}

pub fn delete_record(
    bkey: &[u8],
    bnonce: &[u8],
    locked_safe: &[u8],
    account: &str,
) -> Result<Vec<u8>> {
    let mut records = decrypt(bkey, bnonce, locked_safe)?;

    records = records
        .into_iter()
        .filter(|r| r.account != account)
        .collect();

    return encrypt(bkey, bnonce, records);
}

pub fn fuzzy_search(
    bkey: &[u8],
    bnonce: &[u8],
    locked_safe: &[u8],
    account: &str,
) -> Result<Records> {
    let records = decrypt(bkey, bnonce, locked_safe)?;

    let mut corpus = CorpusBuilder::new().arity(2).pad_full(Pad::Auto).finish();

    for record in records.iter() {
        corpus.add_text(&record.account);
    }

    let results = corpus.search(account, 0.40);

    let mut searched = vec![];
    for result in results.iter() {
        for record in &records {
            if record.account == result.text {
                searched.push(record.clone());
            }
        }
    }

    Ok(Records(searched))
}

#[cfg(test)]
mod tests {

    // #[test]
    // fn encrypt_decrypt() {
    //     let records = vec![
    //         Record {
    //             service: "a".to_owned(),
    //             username: "a2".to_owned(),
    //             password: "a3".to_owned(),
    //             extra: None,
    //         },
    //         Record {
    //             service: "b".to_owned(),
    //             username: "b2".to_owned(),
    //             password: "b3".to_owned(),
    //             extra: None,
    //         },
    //     ];

    //     assert_eq!(result, 4);
    // }
}
