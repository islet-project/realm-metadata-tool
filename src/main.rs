mod cli;
mod commands;
mod crypto;
mod error;
mod manifest;
mod metadata;
mod utils;

use clap::Parser;

use crate::error::Result;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Commands::Create {
            manifest,
            key,
            output,
        } => match commands::create_metadata_file(&manifest, &key, &output) {
            Ok(_) => println!("Metadata file '{}' has been created!", output.display()),
            Err(e) => println!("An error occurred while creating the metadata file: {e}"),
        },
        cli::Commands::Verify { input } => match commands::verify_metadata_file(&input) {
            Ok(result) => match result {
                true => println!(
                    "The signature of '{}' metadata file is valid.",
                    input.display()
                ),
                false => println!(
                    "The signature of '{}' metadata file is invalid!",
                    input.display()
                ),
            },
            Err(e) => println!(
                "An error occurred while verifying '{}' metadata file: {e}",
                input.display()
            ),
        },
        cli::Commands::Dump { input, hexdump } => {
            return commands::dump_metadata_file(&input, hexdump);
        }
    };

    Ok(())
}
