use heapless::Vec;


const MAX_NODES: usize = 32;


pub struct NodeDb {
    ids: Vec<u32, MAX_NODES>,
    keys: Vec<[u8; 32], MAX_NODES>,
}

impl NodeDb {
    pub const fn new() -> Self {
        Self {
            ids: Vec::new(),
            keys: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn set_public_key(&mut self, node_id: u32, public_key: [u8; 32]) {
        if public_key.iter().all(|&b| b == 0) {
            return;
        }

        if let Some(idx) = self.ids.iter().position(|&id| id == node_id) {
            self.keys[idx] = public_key;
            return;
        }

        if self.ids.len() >= MAX_NODES {
            let _ = self.ids.remove(0);
            let _ = self.keys.remove(0);
        }

        let _ = self.ids.push(node_id);
        let _ = self.keys.push(public_key);
    }

    pub fn get_public_key(&self, node_id: u32) -> Option<&[u8; 32]> {
        self.ids
            .iter()
            .position(|&id| id == node_id)
            .map(|idx| &self.keys[idx])
    }
}

impl Default for NodeDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_db_store_and_lookup() {
        let mut db = NodeDb::new();
        let key = [0x11u8; 32];
        db.set_public_key(0x1234, key);
        assert_eq!(db.get_public_key(0x1234).copied(), Some(key));
        assert!(db.get_public_key(0x5678).is_none());

        let key2 = [0x22u8; 32];
        db.set_public_key(0x1234, key2);
        assert_eq!(db.get_public_key(0x1234).copied(), Some(key2));
    }
}
