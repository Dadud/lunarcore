const NUM_RELAYERS: usize = 6;

const HISTORY_SIZE: usize = 32;


#[derive(Clone, Copy)]
struct PacketRecord {
    sender: u32,
    id: u32,
    next_hop: u8,
    hop_limit: u8,
    relayed_by: [u8; NUM_RELAYERS],
}

impl PacketRecord {
    const fn empty() -> Self {
        Self {
            sender: 0,
            id: 0,
            next_hop: 0,
            hop_limit: 0,
            relayed_by: [0; NUM_RELAYERS],
        }
    }
}


pub struct PacketHistory {
    records: [PacketRecord; HISTORY_SIZE],
    index: usize,
}

impl PacketHistory {
    pub const fn new() -> Self {
        Self {
            records: [PacketRecord::empty(); HISTORY_SIZE],
            index: 0,
        }
    }

    fn find_mut(&mut self, sender: u32, id: u32) -> Option<&mut PacketRecord> {
        self.records
            .iter_mut()
            .find(|r| r.sender == sender && r.id == id && r.sender != 0)
    }

    fn find(&self, sender: u32, id: u32) -> Option<&PacketRecord> {
        self.records
            .iter()
            .find(|r| r.sender == sender && r.id == id && r.sender != 0)
    }

    pub fn note_tx(&mut self, sender: u32, id: u32, next_hop: u8, hop_limit: u8, relay_node: u8) {
        if let Some(record) = self.find_mut(sender, id) {
            record.next_hop = next_hop;
            record.hop_limit = hop_limit;
            add_relayer_slot(&mut record.relayed_by, relay_node);
            return;
        }

        let mut record = PacketRecord {
            sender,
            id,
            next_hop,
            hop_limit,
            relayed_by: [0; NUM_RELAYERS],
        };
        add_relayer_slot(&mut record.relayed_by, relay_node);
        self.records[self.index] = record;
        self.index = (self.index + 1) % HISTORY_SIZE;
    }

    pub fn add_relayer(&mut self, sender: u32, id: u32, relay_node: u8) {
        if relay_node == 0 {
            return;
        }
        if let Some(record) = self.find_mut(sender, id) {
            add_relayer_slot(&mut record.relayed_by, relay_node);
            return;
        }
        self.note_tx(sender, id, 0, 0, relay_node);
    }

    pub fn was_relayer(&self, relayer: u8, id: u32, sender: u32) -> (bool, bool) {
        if relayer == 0 {
            return (false, false);
        }
        let Some(record) = self.find(sender, id) else {
            return (false, false);
        };

        let mut count = 0u8;
        let mut matched = false;
        for &r in &record.relayed_by {
            if r != 0 {
                count += 1;
                if r == relayer {
                    matched = true;
                }
            }
        }
        (matched, matched && count == 1)
    }

    pub fn observed_next_hop(&self, sender: u32, id: u32) -> u8 {
        self.find(sender, id).map(|r| r.next_hop).unwrap_or(0)
    }
}

impl Default for PacketHistory {
    fn default() -> Self {
        Self::new()
    }
}


fn add_relayer_slot(slots: &mut [u8; NUM_RELAYERS], relay_node: u8) {
    if relay_node == 0 {
        return;
    }
    for slot in slots.iter_mut() {
        if *slot == relay_node {
            return;
        }
        if *slot == 0 {
            *slot = relay_node;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_tracks_relayers_and_sole() {
        let mut hist = PacketHistory::new();
        hist.note_tx(0xA, 1, 0, 3, 0xA0);
        assert_eq!(hist.was_relayer(0xA0, 1, 0xA), (true, true));

        hist.add_relayer(0xA, 1, 0xB0);
        assert_eq!(hist.was_relayer(0xB0, 1, 0xA), (true, false));
        assert_eq!(hist.was_relayer(0xA0, 1, 0xA), (true, false));
        assert_eq!(hist.was_relayer(0xC0, 1, 0xA), (false, false));
    }
}
