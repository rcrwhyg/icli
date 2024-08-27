use std::os::unix::process;

use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_text_sign,
    Base64SubCommand, Opts, Subcommand, TextSubCommand,
};

fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();
    match opts.cmd {
        Subcommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output, opts.format)?;
        }
        Subcommand::GenPass(opts) => process_genpass(
            opts.length,
            opts.uppercase,
            opts.lowercase,
            opts.number,
            opts.symbol,
        )?,
        Subcommand::Base64(subcmd) => match subcmd {
            Base64SubCommand::Encode(opts) => {
                process_encode(&opts.input, opts.format)?;
            }
            Base64SubCommand::Decode(opts) => {
                process_decode(&opts.input, opts.format)?;
            }
        },
        Subcommand::Text(subcmd) => match subcmd {
            TextSubCommand::Sign(opts) => match opts.format {
                rcli::TextSignFormat::Blake3 => {
                    process_text_sign(&opts.input, &opts.key, opts.format);
                }

                rcli::TextSignFormat::Ed25519 => {
                    println!("Sign with Ed25519")
                }
            },
            TextSubCommand::Verify(opts) => {
                println!("{:?}", opts);
            }
        },
    }

    Ok(())
}
