use heapless::Vec;

pub const FLAG_TX: u8 = 0x03;
pub const FLAG_RX: u8 = 0x04;
pub const FLAG_ACK: u8 = 0x05;
pub const FLAG_MAC: u8 = 0x40;
pub const MAX_RNODE_FRAME_SIZE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkQuality {
    pub rssi_dbm: i16,
    pub snr_db: i8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RNodeFrame {
    pub flags: u8,
    pub channel_index: u8,
    pub link_quality: LinkQuality,
    pub mac: [u8; 4],
    pub payload: Vec<u8, MAX_RNODE_FRAME_SIZE>,
}

impl RNodeFrame {
    pub fn new(flags: u8, channel_index: u8, payload: &[u8], link_quality: LinkQuality) -> Option<Self> {
        if payload.len() > MAX_RNODE_FRAME_SIZE {
            return None;
        }

        let mut frame = Self {
            flags,
            channel_index,
            link_quality,
            mac: [0u8; 4],
            payload: Vec::new(),
        };
        let _ = frame.payload.extend_from_slice(payload);
        frame.mac = frame.compute_mac();
        Some(frame)
    }

    pub fn encode(&self) -> Vec<u8, { MAX_RNODE_FRAME_SIZE + 10 }> {
        let mut out = Vec::new();
        let _ = out.push(self.flags);
        let _ = out.push(self.channel_index);
        let _ = out.push(self.payload.len() as u8);
        let _ = out.extend_from_slice(&self.link_quality.rssi_dbm.to_be_bytes());
        let _ = out.push(self.link_quality.snr_db as u8);
        let _ = out.extend_from_slice(&self.mac);
        let _ = out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }

        let payload_len = data[2] as usize;
        if data.len() != payload_len + 10 || payload_len > MAX_RNODE_FRAME_SIZE {
            return None;
        }

        let mut payload = Vec::new();
        let _ = payload.extend_from_slice(&data[10..]);

        let frame = Self {
            flags: data[0],
            channel_index: data[1],
            link_quality: LinkQuality {
                rssi_dbm: i16::from_be_bytes([data[3], data[4]]),
                snr_db: data[5] as i8,
            },
            mac: [data[6], data[7], data[8], data[9]],
            payload,
        };

        if frame.compute_mac() == frame.mac {
            Some(frame)
        } else {
            None
        }
    }

    fn compute_mac(&self) -> [u8; 4] {
        let mut mac = [0u8; 4];
        mac[0] = self.flags ^ self.channel_index;
        mac[1] = self.link_quality.rssi_dbm.to_be_bytes()[1];
        mac[2] = self.link_quality.snr_db as u8;
        mac[3] = self.payload.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
        mac
    }
}
