use std::time::Instant;
use std::time::Duration;
use std::fmt;

#[derive(Debug)]
pub enum MrpMessageType {
    TestFrame,
    TopologyChange,
    LinkDown,
    LinkUp,
    Other(u8),
}

#[derive(Debug)]
pub struct MrpFrame {
    pub version: u16,
    pub message_type: MrpMessageType,
    pub header_length: u8,
    pub prio: u16,
    pub sa: [u8; 6],
    pub port_role: u16,
    pub ring_state: u16,
    pub transition: u16,
    pub timestamp: u32,
    pub xid: u16,
    pub domain_uuid: [u8; 16],
    pub interval: u16,
    pub blocked: u16,
    pub last_frame: Instant,
    pub frame_distance: Duration,
}

impl MrpFrame {

    /// Construct empty PnDcpPacket from Transaction ID
    pub fn new() -> Self {
        Self {
            version: 0u16,
            message_type: MrpMessageType::Other(0),
            header_length: 0u8,
            prio: 0u16,
            sa: [0u8; 6],
            port_role: 0u16,
            ring_state: 0u16,
            transition: 0u16,
            timestamp: 0u32,
            xid: 0u16,
            domain_uuid: [0u8; 16],
            interval: 0u16,
            blocked: 0u16,
            last_frame: Instant::now(),
            frame_distance: Instant::now().duration_since(Instant::now()),
        }
    }

    pub fn decode_mrp_frame(&mut self, payload: &[u8]) {

        // calculate frame distance
        let now = Instant::now();
        self.frame_distance = now.duration_since(self.last_frame);
        self.last_frame = now;

        self.version = u16::from_be_bytes(payload[0..2].try_into().unwrap());

        self.message_type = match payload[2] {
            0x02 => MrpMessageType::TestFrame,
            0x03 => MrpMessageType::TopologyChange,
            0x04 => MrpMessageType::LinkDown,
            0x05 => MrpMessageType::LinkUp,
            x => MrpMessageType::Other(x),
        };

        self.header_length   = u8::from_be_bytes([payload[3]]);

        match self.message_type {
            MrpMessageType::LinkUp => {
                self.sa              = payload[4..10].try_into().expect("Slice conversion failed");
                self.port_role       = u16::from_be_bytes(payload[10..12].try_into().unwrap());
                self.interval        = u16::from_be_bytes(payload[12..14].try_into().unwrap());
                self.blocked         = u16::from_be_bytes(payload[14..16].try_into().unwrap());
                self.xid             = u16::from_be_bytes(payload[20..22].try_into().unwrap());
                self.domain_uuid     = payload[22..38].try_into().expect("Slice conversion failed");               
            }
            MrpMessageType::LinkDown => {
                self.sa              = payload[4..10].try_into().expect("Slice conversion failed");
                self.port_role       = u16::from_be_bytes(payload[10..12].try_into().unwrap());
                self.interval        = u16::from_be_bytes(payload[12..14].try_into().unwrap());
                self.blocked         = u16::from_be_bytes(payload[14..16].try_into().unwrap());
                self.xid             = u16::from_be_bytes(payload[20..22].try_into().unwrap());
                self.domain_uuid     = payload[22..38].try_into().expect("Slice conversion failed");               
            }

            MrpMessageType::TopologyChange => {
                self.prio            = u16::from_be_bytes(payload[4..6].try_into().unwrap());
                self.sa              = payload[6..12].try_into().expect("Slice conversion failed");
                self.interval        = u16::from_be_bytes(payload[12..14].try_into().unwrap());     
                self.xid             = u16::from_be_bytes(payload[16..18].try_into().unwrap());
                self.domain_uuid     = payload[18..34].try_into().expect("Slice conversion failed");             
            }
            MrpMessageType::TestFrame => {
                let miliseconds      = u32::from_be_bytes(payload[18..22].try_into().unwrap());
                //self.frame_distance  = miliseconds as i64 - self.timestamp as i64;

                self.prio            = u16::from_be_bytes(payload[4..6].try_into().unwrap());
                self.sa              = payload[6..12].try_into().expect("Slice conversion failed");
                self.port_role       = u16::from_be_bytes(payload[12..14].try_into().unwrap());
                self.ring_state      = u16::from_be_bytes(payload[14..16].try_into().unwrap());
                self.transition      = u16::from_be_bytes(payload[16..18].try_into().unwrap());
                self.timestamp       = miliseconds;
                self.xid             = u16::from_be_bytes(payload[24..26].try_into().unwrap());
                self.domain_uuid     = payload[26..42].try_into().expect("Slice conversion failed");

            }
            _ => {
                println!("⚠️ Unknown message type");
            }
        }
    }

    pub fn priority(&self) -> &str {
        match self.prio {
            0xa000 => "Default Auto manager",
            _ => "Unknown",
        }
    }

    pub fn portrole(&self) -> &str {
        match self.port_role {
            0x0000 => "Primary",            
            0x0001 => "Secondary",
            _ => "Unknown",
        }
    }

    pub fn ringstate(&self) -> &str {
        match self.ring_state {
            0x0000 => "Opened",
            0x0001 => "Closed",
            _ => "Unknown",
        }
    }

}

impl fmt::Display for MrpFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sa_mac: &str = &self.sa.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":");

        let domain_uuid = format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            &self.domain_uuid[0], &self.domain_uuid[1], &self.domain_uuid[2], &self.domain_uuid[3],
            &self.domain_uuid[4], &self.domain_uuid[5],
            &self.domain_uuid[6], &self.domain_uuid[7],
            &self.domain_uuid[8], &self.domain_uuid[9],
            &self.domain_uuid[10], &self.domain_uuid[11], &self.domain_uuid[12], &self.domain_uuid[13], &self.domain_uuid[14], &self.domain_uuid[15]
        );

        write!(f, "{:>4}ms {:>15} SA: {}, UUID: {} XID: {:<6} Interval: {:2}ms port role: {:<10} ring state: {:<8} transition: {} ",
            self.frame_distance.as_millis(), 
            format!("{:?}", self.message_type), 
            sa_mac, domain_uuid, 
            self.xid, 
            self.interval, 
            self.portrole(), 
            self.ringstate(),
            self.transition
        )?;

        Ok(())
    }
}