use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, SetPriorityClass, SetThreadPriority,
    REALTIME_PRIORITY_CLASS, THREAD_PRIORITY_HIGHEST, 
};

use std::io;
use std::io::Write;
use clap::{Arg, Command};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, Packet};

use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::MutablePacket;

use mrp::{MrpFrame, MrpMessageType};

fn main() {
    let matches = Command::new("Siemens PUT/GET Parser")
    .version("1.0")
    .about("Listens for Siemens S7 PUT/GET traffic and parses it")

    // interface
    .arg(
        Arg::new("interface")
            .short('i')
            .long("interface")
            .num_args(1)
            .required(true)
            .help("IP address or MAC address of the interface to listen on"),
    )

    // fault filter
    .arg(
        Arg::new("spoof")
            .short('s')
            .long("spoof")
            .help("Send spoof frames")
            .action(clap::ArgAction::SetTrue),
    )

    // fault filter
    .arg(
        Arg::new("all")
            .short('a')
            .long("all")
            .help("Include test frames")
            .action(clap::ArgAction::SetTrue),
    )

    .get_matches();
    
    // We dont want to put aside while calculating and sending the time
    enter_critical_mode();

    // Get parser values
    let interface_name = matches.get_one::<String>("interface").unwrap();
    let print_all = matches.get_flag("all");
    let spoof = matches.get_flag("spoof");

    // Get interface
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| {
        iface.ips.iter().any(|ip| ip.ip().to_string() == *interface_name)
            || iface.mac.map(|mac| normalize_mac(mac.to_string())) == Some(normalize_mac(interface_name.to_string()))
    });

    let interface = match interface {
        Some(iface) => iface,
        None => {
            eprintln!("Error: No matching interface found for {}", interface_name);
            return;
        }
    };

    println!("Starting packet handler");
    io::stdout().flush().unwrap();
    
    let mut mrp = MrpFrame::new();

    // ethernet frame
    let tst_mac = [0x01, 0x15, 0x4e, 0x00, 0x00, 0x01]; // MRP topology change/linkupdown multicast mac
    let dst_mac = [0x01, 0x15, 0x4e, 0x00, 0x00, 0x02]; // MRP test frame multicast mac

    let mut src_mac = mrp.sa;

    // Prepare raw Ethernet frame buffer
    let mut buffer = [0u8; 60];
    let mut spoof_frame = MutableEthernetPacket::new(&mut buffer).unwrap();

    // construct ethernet frame
    spoof_frame.set_destination(dst_mac.into());
    spoof_frame.set_source(src_mac.into());
    spoof_frame.set_ethertype(EtherType(0x88e3));
    
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(mut tx, mut rx)) => {
            loop {
                // Try to get a packet
                match rx.next() {
                    Ok(packet) => {
                        if let Some(eth) = EthernetPacket::new(packet) {
                            if eth.get_ethertype().0 == 0x88e3 {
 
                                // decode MRP frame
                                let payload = eth.payload();
                                mrp.decode_mrp_frame(payload);

                                // check if we have to print the test frames
                                if print_all {
                                    println!("{}", mrp);
                                } else {
                                    if let MrpMessageType::TestFrame = mrp.message_type {
                                    } else {
                                        println!("{}", mrp);
                                    }
                                }
                                io::stdout().flush().unwrap();

                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️ Error reading packet: {}", e);
                        // or handle it as you like
                    }
                }

            }
        }
        Ok(_) => println!("⚠️ Unknown channel type for {}", interface.name),
        Err(e) => println!("⚠️ Failed to listen on {}: {}", interface.name, e),
    }
    
}

fn enter_critical_mode() {
    unsafe {
        // Set the process priority to real-time
        if SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS).is_err() {
            eprintln!("⚠️ Failed to set process priority to real-time.");
        }

        // Set the thread priority to time-critical
        if SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST).is_err() {
            eprintln!("⚠️ Failed to set thread priority to time-critical.");
        }

        println!("🚀 Entered priority mode.");
    }
}

fn normalize_mac(mac: String) -> String {
    mac.to_lowercase().replace('-', ":") // Convert dashes to colons and lowercase
}