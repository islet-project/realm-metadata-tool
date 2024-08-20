use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Available commands
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Create {
        /// Path to the manifest file (.yaml)
        #[arg(short, long)]
        manifest: PathBuf,

        /// Path to the EC P384 private key file (.pem)
        #[arg(short, long)]
        key: PathBuf,

        /// The resulting realm metadata file
        #[arg(short, long)]
        output: PathBuf,
    },

    Verify {
        /// Path to the realm metadata file
        #[arg(short, long)]
        input: PathBuf,
    },

    Dump {
        /// Path to the realm metadata file
        #[arg(short, long)]
        input: PathBuf,

        /// Dump metadata structure in a hexadecimal format
        #[arg(long)]
        hexdump: bool,
    },
}
