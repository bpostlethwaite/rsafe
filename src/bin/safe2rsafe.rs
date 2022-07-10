use anyhow::Result;
use rsafe::{encrypt, Record};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::fs;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OldRecord {
    service: String,
    username: String,
    password: String,
    extra: Option<String>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: safe2rsafe UNLOCKED_OLD_SAFE_FILE LOCKED_NEW_SAFEFILE_PATH")
    }

    let old_safe_path = &args[1];
    let new_safe_path = &args[2];
    let data = fs::read(old_safe_path)?;

    let old_safe: HashMap<String, OldRecord> = serde_json::from_str(std::str::from_utf8(&data)?)?;

    let skey = rpassword::prompt_password("password: ")?;
    let bkey = skey.as_bytes();
    let bnonce = b"safe is safe"; // must be 12 bytes

    let mut records: Vec<Record> = vec![];
    for (_, old_record) in old_safe {
        records.push(Record {
            account: old_record.service,
            username: old_record.username,
            password: old_record.password,
            extra: old_record.extra,
        });
    }

    let locked_safe = encrypt(bkey, bnonce, records)?;

    fs::write(new_safe_path, locked_safe)?;

    Ok(())
}
