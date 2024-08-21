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
        #[arg(short, long, default_value = "manifest.yaml")]
        manifest: PathBuf,

        /// Path to the EC P384 private key file (.pem)
        #[arg(short, long, default_value = "private.pem")]
        key: PathBuf,

        /// The resulting realm metadata file
        #[arg(short, long, default_value = "metadata.bin")]
        output: PathBuf,
    },

    Verify {
        /// Path to the realm metadata file
        #[arg(short, long, default_value = "metadata.bin")]
        input: PathBuf,
    },

    Dump {
        /// Path to the realm metadata file
        #[arg(short, long, default_value = "metadata.bin")]
        input: PathBuf,

        /// Dump metadata structure in a hexadecimal format
        #[arg(long)]
        hexdump: bool,
    },
}
