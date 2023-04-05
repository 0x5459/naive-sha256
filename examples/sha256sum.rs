use std::{
    fs,
    io::{self, BufRead, BufReader},
    path::PathBuf,
};

use clap::Parser;

/// Compute SHA256 (256-bit) checksums.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// read in binary mode
    #[arg(short, long)]
    binary: bool,
    /// read in text mode (default)
    #[arg(short, long, default_value_t = true)]
    text: bool,
    /// With no FILE, or when FILE is -, read standard input.
    file: Option<PathBuf>,
}

const STDIN_NAME: &'static str = "-";

fn main() -> io::Result<()> {
    let args = Args::parse();

    let box_stdin = || Box::new(BufReader::new(io::stdin())) as Box<dyn BufRead>;
    let mut reader = match args.file {
        None => box_stdin(),
        Some(x) if x.to_str() == Some(STDIN_NAME) => box_stdin(),
        Some(file) => Box::new(BufReader::new(fs::File::open(file)?)) as Box<dyn BufRead>,
    };

    let mut hasher = naive_sha256::Sha256::new();
    loop {
        let buf = reader.fill_buf()?;
        // EOF
        if buf.is_empty() {
            break;
        }
        hasher.update(&buf);
        let len = buf.len();
        reader.consume(len);
    }
    println!("{}", hex::encode(hasher.finalize()));
    Ok(())
}
