extern crate byteorder;
extern crate clap;

use byteorder::{LittleEndian, WriteBytesExt};
use clap::{Arg, App, AppSettings, Shell};
use std::fs::File;
use std::io::{BufWriter, Result as IoResult, stdout};
use std::io::prelude::*;
use std::str::FromStr;

// copied from ether

/// PCAP Header
///
/// * magic number (0xA1B23C4D)
/// * major version number
/// * minor version number
/// * GMT to local correction
/// * accuracy of timestamps (typically ignored as 0)
/// * max length of captured packets, in octets
/// * data link type
///
#[derive(Debug)]
pub struct PcapHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: Link,
}

/// Link types as defined in http://www.tcpdump.org/linktypes.html
#[derive(Debug)]
pub enum Link {
    Null,
    Ethernet,
    Unknown(u32),
}

/// PcapRecordHeader entry in a packet capture
///
/// * timestamp seconds
/// * timestamp nanoseconds
/// * number of octets of packet saved in file
/// * actual length of packet
#[derive(Debug)]
pub struct PcapRecordHeader<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    pub payload: &'a Vec<u8>,
}

fn main() {
    do_main().unwrap()
}

fn do_main() -> IoResult<()> {
    let matches = build_cli().get_matches();

    if let Some(shell) = matches.value_of("shell_completions") {
            let mut cli = build_cli();
            let bin_name = {
                cli.get_bin_name().unwrap_or("pcapgen").to_string()
            };
            cli.gen_completions_to(bin_name, FromStr::from_str(shell).unwrap(), &mut stdout());
            return Ok(());
    }

    let mut outfile = BufWriter::new(File::create(matches.value_of_os("pcapfile").unwrap())?);
    let mut databuf = Vec::with_capacity(2048);
    // DLT_RAW header: encapsulates raw IP and IPv6 packets
    let header = PcapHeader::new(Link::Unknown(101));
    header.serialize(&mut outfile)?;

    for path in matches.values_of("ip_packets").unwrap() {
        databuf.truncate(0);
        println!("Processing {}", path);
        let mut infile = File::open(path)?;
        infile.read_to_end(&mut databuf)?;
        let rheader = PcapRecordHeader::new(&databuf);
        rheader.serialize(&mut outfile)?;
        outfile.flush()?;
    }
    outfile.flush()?;

    Ok(())
}

fn build_cli() -> App<'static, 'static> {
    App::new("pcapgen")
        .version("1.0")
        .author("Jonas Bushart")
        .about("Merge many IP packets into a pcap file.")
        .arg(Arg::with_name("pcapfile")
                 .short("o")
                 .long("output")
                 .value_name("FILE")
                 .help("Path to the output pcap file")
                 .required(true)
                 .required_unless("shell_completions")
                 .next_line_help(true)
                 .takes_value(true))
        .arg(Arg::with_name("ip_packets")
                 .value_name("PATH")
                 .required(true)
                 .required_unless("shell_completions")
                 .help("Path to files containing IP packets")
                 .next_line_help(true)
                 .multiple(true))
        // TODO start time
        // TODO time increment
        .arg(Arg::with_name("shell_completions")
                 .long("shell-completions")
                 .help("Generate shell tab completion files")
                 .takes_value(true)
                 .possible_values(&Shell::variants()))
        .settings(&[AppSettings::ColoredHelp,
                    AppSettings::NextLineHelp,
                    AppSettings::TrailingVarArg,
                    AppSettings::UnifiedHelpMessage])
}

impl PcapHeader {
    fn new(network: Link) -> PcapHeader {
        PcapHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 1 << 16,
            network: network,
        }
    }

    fn serialize<W: Write + WriteBytesExt>(&self, out: &mut W) -> IoResult<()> {
        out.write_u32::<LittleEndian>(self.magic_number)?;
        out.write_u16::<LittleEndian>(self.version_major)?;
        out.write_u16::<LittleEndian>(self.version_minor)?;
        out.write_i32::<LittleEndian>(self.thiszone)?;
        out.write_u32::<LittleEndian>(self.sigfigs)?;
        out.write_u32::<LittleEndian>(self.snaplen)?;
        self.network.serialize(out)?;
        Ok(())
    }
}

impl From<u32> for Link {
    fn from(link: u32) -> Self {
        match link {
            0 => Link::Null,
            1 => Link::Ethernet,
            otherwise => Link::Unknown(otherwise),
        }
    }
}

impl Link {
    fn serialize<W: Write + WriteBytesExt>(&self, out: &mut W) -> IoResult<()> {
        out.write_u32::<LittleEndian>(match *self {
                                        Link::Null => 0,
                                        Link::Ethernet => 1,
                                        Link::Unknown(otherwise) => otherwise,
                                    })?;
        Ok(())
    }
}

impl<'a> PcapRecordHeader<'a> {
    fn new(data: &'a Vec<u8>) -> PcapRecordHeader<'a> {
        PcapRecordHeader {
            ts_sec: 9965,
            ts_usec: 4423,
            incl_len: data.len() as u32,
            orig_len: data.len() as u32,
            payload: data,
        }
    }

    fn serialize<W: Write + WriteBytesExt>(&self, out: &mut W) -> IoResult<()> {
        out.write_u32::<LittleEndian>(self.ts_sec)?;
        out.write_u32::<LittleEndian>(self.ts_usec)?;
        out.write_u32::<LittleEndian>(self.incl_len)?;
        out.write_u32::<LittleEndian>(self.orig_len)?;
        out.write(self.payload)?;
        Ok(())
    }
}
