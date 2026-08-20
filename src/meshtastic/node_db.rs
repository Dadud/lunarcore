use heapless::Vec;


const MAX_NODES: usize = 32;

const NVS_NAMESPACE: &[u8] = b"mesh_nodes\0";

const NVS_COUNT_KEY: &[u8] = b"node_count\0";


#[derive(Clone, Copy)]
pub struct NodeRecord {
    pub node_id: u32,
    pub public_key: [u8; 32],
    pub next_hop: u8,
}

impl NodeRecord {
    pub const fn serialized_size() -> usize {
        4 + 32 + 1
    }

    pub fn serialize(&self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.node_id.to_le_bytes());
        out[4..36].copy_from_slice(&self.public_key);
        out[36] = self.next_hop;
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < Self::serialized_size() {
            return None;
        }
        let node_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[4..36]);
        Some(Self {
            node_id,
            public_key,
            next_hop: data[36],
        })
    }
}


pub struct NodeDb {
    records: Vec<NodeRecord, MAX_NODES>,
}

impl NodeDb {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn set_public_key(&mut self, node_id: u32, public_key: [u8; 32]) {
        if public_key.iter().all(|&b| b == 0) {
            return;
        }

        if let Some(record) = self.records.iter_mut().find(|r| r.node_id == node_id) {
            record.public_key = public_key;
            return;
        }

        if self.records.len() >= MAX_NODES {
            let _ = self.records.remove(0);
        }

        let _ = self.records.push(NodeRecord {
            node_id,
            public_key,
            next_hop: 0,
        });
    }

    pub fn set_next_hop(&mut self, node_id: u32, next_hop: u8) {
        if next_hop == 0 {
            return;
        }

        if let Some(record) = self.records.iter_mut().find(|r| r.node_id == node_id) {
            record.next_hop = next_hop;
            return;
        }

        if self.records.len() >= MAX_NODES {
            let _ = self.records.remove(0);
        }

        let _ = self.records.push(NodeRecord {
            node_id,
            public_key: [0u8; 32],
            next_hop,
        });
    }

    pub fn get_public_key(&self, node_id: u32) -> Option<&[u8; 32]> {
        self.records
            .iter()
            .find(|r| r.node_id == node_id)
            .map(|r| &r.public_key)
    }

    pub fn get_next_hop(&self, node_id: u32) -> Option<u8> {
        self.records
            .iter()
            .find(|r| r.node_id == node_id)
            .map(|r| r.next_hop)
    }

    pub fn next_hop_hint(&self, node_id: u32) -> u8 {
        self.get_next_hop(node_id).unwrap_or(0)
    }

    pub fn clear_next_hop(&mut self, node_id: u32) {
        if let Some(record) = self.records.iter_mut().find(|r| r.node_id == node_id) {
            record.next_hop = 0;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &NodeRecord> {
        self.records.iter()
    }

    #[cfg(target_arch = "xtensa")]
    pub fn save_to_nvs(&self) -> Result<(), ()> {
        use esp_idf_sys::*;

        unsafe {
            let mut handle: nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_ptr(NVS_NAMESPACE.as_ptr() as *const core::ffi::c_char);
            let mut err = nvs_open(namespace.as_ptr(), nvs_open_mode_t_NVS_READWRITE, &mut handle);
            if err != ESP_OK {
                nvs_flash_init();
                err = nvs_open(namespace.as_ptr(), nvs_open_mode_t_NVS_READWRITE, &mut handle);
            }
            if err != ESP_OK {
                return Err(());
            }

            let count_key = core::ffi::CStr::from_ptr(NVS_COUNT_KEY.as_ptr() as *const core::ffi::c_char);
            nvs_set_u32(handle, count_key.as_ptr(), self.records.len() as u32);

            for (idx, record) in self.records.iter().enumerate() {
                let mut key_name = [0u8; 16];
                key_name[..5].copy_from_slice(b"node_");
                key_name[5] = b'0' + (idx / 10) as u8;
                key_name[6] = b'0' + (idx % 10) as u8;
                key_name[7] = 0;
                let key = core::ffi::CStr::from_ptr(key_name.as_ptr() as *const core::ffi::c_char);

                let mut blob = [0u8; NodeRecord::serialized_size()];
                record.serialize(&mut blob);
                nvs_set_blob(
                    handle,
                    key.as_ptr(),
                    blob.as_ptr() as *const _,
                    blob.len(),
                );
            }

            nvs_commit(handle);
            nvs_close(handle);
        }

        Ok(())
    }

    #[cfg(target_arch = "xtensa")]
    pub fn load_from_nvs(&mut self) -> Result<usize, ()> {
        use esp_idf_sys::*;

        unsafe {
            let mut handle: nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_ptr(NVS_NAMESPACE.as_ptr() as *const core::ffi::c_char);
            if nvs_open(namespace.as_ptr(), nvs_open_mode_t_NVS_READONLY, &mut handle) != ESP_OK {
                return Ok(0);
            }

            let count_key = core::ffi::CStr::from_ptr(NVS_COUNT_KEY.as_ptr() as *const core::ffi::c_char);
            let mut count: u32 = 0;
            if nvs_get_u32(handle, count_key.as_ptr(), &mut count) != ESP_OK {
                nvs_close(handle);
                return Ok(0);
            }

            let count = core::cmp::min(count as usize, MAX_NODES);
            self.records.clear();
            let mut loaded = 0;

            for idx in 0..count {
                let mut key_name = [0u8; 16];
                key_name[..5].copy_from_slice(b"node_");
                key_name[5] = b'0' + (idx / 10) as u8;
                key_name[6] = b'0' + (idx % 10) as u8;
                key_name[7] = 0;
                let key = core::ffi::CStr::from_ptr(key_name.as_ptr() as *const core::ffi::c_char);

                let mut blob = [0u8; NodeRecord::serialized_size()];
                let mut blob_len = blob.len();
                if nvs_get_blob(
                    handle,
                    key.as_ptr(),
                    blob.as_mut_ptr() as *mut _,
                    &mut blob_len,
                ) == ESP_OK
                {
                    if let Some(record) = NodeRecord::deserialize(&blob[..blob_len]) {
                        let _ = self.records.push(record);
                        loaded += 1;
                    }
                }
            }

            nvs_close(handle);
            Ok(loaded)
        }
    }

    #[cfg(not(target_arch = "xtensa"))]
    pub fn save_to_nvs(&self) -> Result<(), ()> {
        Ok(())
    }

    #[cfg(not(target_arch = "xtensa"))]
    pub fn load_from_nvs(&mut self) -> Result<usize, ()> {
        Ok(0)
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

        db.set_next_hop(0x1234, 0x42);
        assert_eq!(db.get_next_hop(0x1234), Some(0x42));
    }

    #[test]
    fn test_node_record_roundtrip() {
        let record = NodeRecord {
            node_id: 0xAABBCCDD,
            public_key: [0x55u8; 32],
            next_hop: 0x7E,
        };
        let mut buf = [0u8; NodeRecord::serialized_size()];
        record.serialize(&mut buf);
        let decoded = NodeRecord::deserialize(&buf).unwrap();
        assert_eq!(decoded.node_id, record.node_id);
        assert_eq!(decoded.public_key, record.public_key);
        assert_eq!(decoded.next_hop, record.next_hop);
    }
}
