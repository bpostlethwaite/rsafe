// Note: this requires the `cargo` feature

use anyhow::Result;
use clap::{arg, Command};
use rpassword;
use rsafe::{delete_record, fuzzy_search, put_record, Record, Records};
use std::fs;
use std::path::Path;

fn cli() -> Command<'static> {
    Command::new("rsafe")
        .about("Secrets Manager")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .allow_invalid_utf8_for_external_subcommands(true)
        .arg(arg!(-s --safepath <SAFE_PATH> "Path to safe file").required(false))
        .subcommand(
            Command::new("search")
                .about("fuzzy search records")
                .arg(arg!(<ACCOUNT> "The record account name to fuzzy search for"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("put")
                .about("puts a new record into the safe")
                .arg(arg!(<ACCOUNT> "The account name").required(true))
                .arg(arg!(<USERNAME> "The username").required(true))
                .arg(arg!(<PASSWORD> "The password").required(true))
                .arg(arg!(<EXTRA> "Any extras associated with the account").required(false))
                .arg_required_else_help(true),
        )

    // .subcommand(
    //     Command::new("add")
    //         .about("adds things")
    //         .arg_required_else_help(true)
    //         .arg(arg!(<PATH> ... "Stuff to add").value_parser(clap::value_parser!(PathBuf))),
    // )
    // .subcommand(
    //     Command::new("stash")
    //         .args_conflicts_with_subcommands(true)
    //         .args(push_args())
    //         .subcommand(Command::new("push").args(push_args()))
    //         .subcommand(Command::new("pop").arg(arg!([STASH])))
    //         .subcommand(Command::new("apply").arg(arg!([STASH]))),
    // )
}

fn read_safe(safe_path: &str) -> Result<Vec<u8>> {
    if Path::new(safe_path).exists() {
        Ok(fs::read(safe_path)?)
    } else {
        Ok(vec![])
    }
}

fn write_safe(safe_path: &str, locked_safe: Vec<u8>) -> Result<()> {
    fs::write(safe_path, locked_safe)?;
    Ok(())
}

fn main() -> Result<()> {
    let matches = cli().get_matches();

    let mut safe_path = "/home/ben/rsafe.locked";
    if let Some(user_safe_path) = matches.get_one::<String>("safepath") {
        safe_path = user_safe_path;
    }

    let cmd = matches.subcommand();

    let skey = rpassword::prompt_password("password: ")?;
    let bkey = skey.as_bytes();
    let bnonce = b"safe is safe"; // must be 12 bytes

    match cmd {
        Some(("search", sub_matches)) => {
            let account = sub_matches.get_one::<String>("ACCOUNT").expect("required");
            let locked_safe = read_safe(safe_path)?;
            let records: Records = fuzzy_search(bkey, bnonce, &locked_safe, account)?;
            print!("{records}");
        }
        Some(("put", sub_matches)) => {
            let mut locked_safe = read_safe(safe_path)?;
            let record = Record {
                account: sub_matches
                    .get_one::<String>("ACCOUNT")
                    .expect("required")
                    .clone(),
                username: sub_matches
                    .get_one::<String>("USERNAME")
                    .expect("required")
                    .clone(),
                password: sub_matches
                    .get_one::<String>("PASSWORD")
                    .expect("required")
                    .clone(),
                extra: sub_matches.get_one::<String>("EXTRA").map(|v| v.clone()),
            };
            locked_safe = put_record(bkey, bnonce, &locked_safe, record)?;
            write_safe(safe_path, locked_safe)?
        }
        Some(("delete", sub_matches)) => {
            let account = sub_matches.get_one::<String>("ACCOUNT").expect("required");
            let locked_safe = read_safe(safe_path)?;
            delete_record(bkey, bnonce, &locked_safe, account)?;
        }

        // Some(("add", sub_matches)) => {
        //     let paths = sub_matches
        //         .get_many("PATH")
        //         .into_iter()
        //         .flatten()
        //         .collect::<Vec<_>>();
        //     println!("Adding {:?}", paths);
        // }
        // Some(("stash", sub_matches)) => {
        //     let stash_command = sub_matches.subcommand().unwrap_or(("push", sub_matches));
        //     match stash_command {
        //         ("apply", sub_matches) => {
        //             let stash = sub_matches.get_one::<String>("STASH");
        //             println!("Applying {:?}", stash);
        //         }
        //         ("pop", sub_matches) => {
        //             let stash = sub_matches.get_one::<String>("STASH");
        //             println!("Popping {:?}", stash);
        //         }
        //         ("push", sub_matches) => {
        //             let message = sub_matches.get_one::<String>("message");
        //             println!("Pushing {:?}", message);
        //         }
        //         (name, _) => {
        //             unreachable!("Unsupported subcommand `{}`", name)
        //         }
        //     }
        // }
        // Some((ext, sub_matches)) => {
        //     let args = sub_matches
        //         .get_many::<OsString>("")
        //         .into_iter()
        //         .flatten()
        //         .collect::<Vec<_>>();
        //     println!("Calling out to {:?} with {:?}", ext, args);
        // }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }

    // Continued program logic goes here...
    Ok(())
}
