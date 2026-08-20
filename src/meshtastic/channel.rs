use heapless::Vec;
use crate::crypto::aes::{Aes128, Aes256};
use crate::crypto::sha256::Sha256;
use crate::crypto::hkdf::meshtastic as mesh_kdf;


pub const MAX_CHANNEL_NAME: usize = 12;


pub const KEY_SIZE_128: usize = 16;


pub const KEY_SIZE_256: usize = 32;


pub const NONCE_SIZE: usize = 16;


pub fn xor_bytes(data: &[u8]) -> u8 {
    let mut h = 0u8;
    for &b in data {
        h ^= b;
    }
    h
}


pub fn modem_preset_display_name(preset: ModemPreset) -> &'static str {
    match preset {
        ModemPreset::LongSlow => "LongSlow",
        ModemPreset::LongFast => "LongFast",
        ModemPreset::LongModerate => "LongModerate",
        ModemPreset::VeryLongSlow => "VeryLongSlow",
        ModemPreset::MediumSlow => "MediumSlow",
        ModemPreset::MediumFast => "MediumFast",
        ModemPreset::ShortSlow => "ShortSlow",
        ModemPreset::ShortFast => "ShortFast",
        ModemPreset::ShortTurbo => "ShortTurbo",
    }
}


pub fn resolve_channel_name(name: &str, modem_preset: ModemPreset, use_preset: bool) -> String {
    if name.is_empty() {
        if use_preset {
            return modem_preset_display_name(modem_preset).to_string();
        }
        return "Custom".to_string();
    }
    name.to_string()
}


pub fn expand_psk(psk: &[u8]) -> Option<(Vec<u8, 32>, bool)> {
    if psk.is_empty() {
        return Some((Vec::new(), false));
    }

    if psk.len() == 1 {
        let index = psk[0];
        if index == 0 {
            return Some((Vec::new(), false));
        }
        let mut key = mesh_kdf::DEFAULT_KEY;
        key[15] = key[15].wrapping_add(index - 1);
        let mut buf = Vec::new();
        buf.extend_from_slice(&key).ok()?;
        return Some((buf, true));
    }

    if psk.len() < 16 {
        let mut key = [0u8; KEY_SIZE_128];
        key[..psk.len()].copy_from_slice(psk);
        let mut buf = Vec::new();
        buf.extend_from_slice(&key).ok()?;
        return Some((buf, true));
    }

    if psk.len() == 16 {
        let mut buf = Vec::new();
        buf.extend_from_slice(psk).ok()?;
        return Some((buf, true));
    }

    if psk.len() < 32 {
        let mut key = [0u8; KEY_SIZE_256];
        key[..psk.len()].copy_from_slice(psk);
        let mut buf = Vec::new();
        buf.extend_from_slice(&key).ok()?;
        return Some((buf, true));
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&psk[..KEY_SIZE_256]).ok()?;
    Some((buf, true))
}


pub fn channel_hash(name: &str, key_bytes: &[u8]) -> u8 {
    let name_hash = xor_bytes(name.as_bytes());
    if key_bytes.is_empty() {
        return name_hash;
    }
    name_hash ^ xor_bytes(key_bytes)
}


pub fn match_default_preset_key(hash: u8) -> Option<ChannelKey> {
    const PRESETS: [ModemPreset; 9] = [
        ModemPreset::LongSlow,
        ModemPreset::LongFast,
        ModemPreset::LongModerate,
        ModemPreset::VeryLongSlow,
        ModemPreset::MediumSlow,
        ModemPreset::MediumFast,
        ModemPreset::ShortSlow,
        ModemPreset::ShortFast,
        ModemPreset::ShortTurbo,
    ];

    for preset in PRESETS {
        let name = modem_preset_display_name(preset);
        if channel_hash(name, mesh_kdf::DEFAULT_KEY.as_slice()) == hash {
            return Some(ChannelKey::default_key());
        }
    }
    None
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModemPreset {

    LongSlow = 0,

    LongFast = 1,

    LongModerate = 2,

    VeryLongSlow = 3,

    MediumSlow = 4,

    MediumFast = 5,

    ShortSlow = 6,

    ShortFast = 7,

    ShortTurbo = 8,
}

impl Default for ModemPreset {
    fn default() -> Self {
        ModemPreset::LongFast
    }
}


#[derive(Debug, Clone, Copy)]
pub struct LoraParams {

    pub spreading_factor: u8,

    pub bandwidth: u32,

    pub coding_rate: u8,
}

impl ModemPreset {

    pub const fn lora_params(&self) -> LoraParams {
        match self {
            ModemPreset::LongSlow => LoraParams {
                spreading_factor: 12,
                bandwidth: 125_000,
                coding_rate: 8,
            },
            ModemPreset::LongFast => LoraParams {
                spreading_factor: 11,
                bandwidth: 125_000,
                coding_rate: 8,
            },
            ModemPreset::LongModerate => LoraParams {
                spreading_factor: 11,
                bandwidth: 125_000,
                coding_rate: 5,
            },
            ModemPreset::VeryLongSlow => LoraParams {
                spreading_factor: 12,
                bandwidth: 125_000,
                coding_rate: 8,
            },
            ModemPreset::MediumSlow => LoraParams {
                spreading_factor: 10,
                bandwidth: 250_000,
                coding_rate: 5,
            },
            ModemPreset::MediumFast => LoraParams {
                spreading_factor: 9,
                bandwidth: 250_000,
                coding_rate: 5,
            },
            ModemPreset::ShortSlow => LoraParams {
                spreading_factor: 8,
                bandwidth: 250_000,
                coding_rate: 5,
            },
            ModemPreset::ShortFast => LoraParams {
                spreading_factor: 7,
                bandwidth: 250_000,
                coding_rate: 5,
            },
            ModemPreset::ShortTurbo => LoraParams {
                spreading_factor: 7,
                bandwidth: 500_000,
                coding_rate: 5,
            },
        }
    }


    pub fn airtime_ms(&self, payload_bytes: usize) -> u32 {
        let params = self.lora_params();
        let sf = params.spreading_factor as f32;
        let bw = params.bandwidth as f32;
        let cr = params.coding_rate as f32;


        let t_sym = (2.0_f32.powf(sf)) / bw * 1000.0;
        let t_preamble = (8.0 + 4.25) * t_sym;


        let pl = payload_bytes as f32;
        let de = if sf >= 11.0 { 1.0 } else { 0.0 };
        let h = 0.0;
        let crc = 1.0;

        let numerator = 8.0 * pl - 4.0 * sf + 28.0 + 16.0 * crc - 20.0 * h;
        let denominator = 4.0 * (sf - 2.0 * de);
        let n_payload = 8.0 + (numerator / denominator).ceil().max(0.0) * (cr + 4.0);

        let t_payload = n_payload * t_sym;

        (t_preamble + t_payload) as u32
    }
}


#[derive(Clone)]
pub enum ChannelKey {

    None,

    Aes128([u8; KEY_SIZE_128]),

    Aes256([u8; KEY_SIZE_256]),
}

impl Drop for ChannelKey {
    fn drop(&mut self) {

        match self {
            ChannelKey::None => {}
            ChannelKey::Aes128(key) => {
                crate::crypto::secure_zero(key);
            }
            ChannelKey::Aes256(key) => {
                crate::crypto::secure_zero(key);
            }
        }
    }
}

impl ChannelKey {

    pub fn from_psk(psk: &[u8]) -> Self {
        let (expanded, encrypted) = expand_psk(psk).unwrap_or((Vec::new(), false));
        if !encrypted {
            return ChannelKey::None;
        }
        match expanded.len() {
            KEY_SIZE_128 => {
                let mut k = [0u8; KEY_SIZE_128];
                k.copy_from_slice(&expanded[..KEY_SIZE_128]);
                ChannelKey::Aes128(k)
            }
            _ => {
                let mut k = [0u8; KEY_SIZE_256];
                k.copy_from_slice(&expanded[..KEY_SIZE_256]);
                ChannelKey::Aes256(k)
            }
        }
    }

    pub fn from_bytes(key: &[u8]) -> Self {
        Self::from_psk(key)
    }


    pub fn default_key() -> Self {
        ChannelKey::from_psk(&[0x01])
    }


    pub fn from_channel_name(name: &str) -> Self {
        if name.is_empty() {
            return Self::default_key();
        }
        let hash = mesh_kdf::derive_channel_key(name);
        ChannelKey::Aes256(hash)
    }


    pub fn is_encrypted(&self) -> bool {
        !matches!(self, ChannelKey::None)
    }


    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ChannelKey::None => &[],
            ChannelKey::Aes128(k) => k,
            ChannelKey::Aes256(k) => k,
        }
    }
}

impl Default for ChannelKey {
    fn default() -> Self {
        ChannelKey::default_key()
    }
}

impl core::fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelKey::None => write!(f, "ChannelKey::None"),
            ChannelKey::Aes128(_) => write!(f, "ChannelKey::Aes128([REDACTED])"),
            ChannelKey::Aes256(_) => write!(f, "ChannelKey::Aes256([REDACTED])"),
        }
    }
}


#[derive(Clone)]
pub struct Channel {

    pub index: u8,

    pub name: Vec<u8, MAX_CHANNEL_NAME>,

    pub key: ChannelKey,

    pub modem_preset: ModemPreset,

    pub uplink_enabled: bool,

    pub downlink_enabled: bool,

    pub position_precision: u8,
}

impl Channel {

    pub fn new(index: u8) -> Self {
        Self {
            index,
            name: Vec::new(),
            key: ChannelKey::default_key(),
            modem_preset: ModemPreset::default(),
            uplink_enabled: false,
            downlink_enabled: false,
            position_precision: 0,
        }
    }


    pub fn primary() -> Self {
        Self::new(0)
    }


    pub fn set_name(&mut self, name: &str) {
        self.name.clear();
        let len = core::cmp::min(name.len(), MAX_CHANNEL_NAME);
        self.name.extend_from_slice(&name.as_bytes()[..len]).ok();
    }


    pub fn set_key(&mut self, key: &[u8]) {
        self.key = ChannelKey::from_psk(key);
    }


    pub fn effective_name(&self) -> String {
        resolve_channel_name(self.name_str(), self.modem_preset, true)
    }


    pub fn encrypt(&self, packet_id: u32, sender: u32, plaintext: &[u8]) -> Option<Vec<u8, 256>> {
        if !self.key.is_encrypted() {

            return Vec::from_slice(plaintext).ok();
        }


        let nonce = mesh_kdf::derive_nonce(packet_id, sender);


        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(plaintext).ok()?;

        match &self.key {
            ChannelKey::Aes128(key) => {
                let cipher = Aes128::new(key);

                let mut nonce_block = [0u8; 16];
                nonce_block.copy_from_slice(&nonce);
                cipher.encrypt_ctr(&nonce_block, &mut ciphertext);
            }
            ChannelKey::Aes256(key) => {
                let cipher = Aes256::new(key);
                let mut nonce_block = [0u8; 16];
                nonce_block.copy_from_slice(&nonce);
                cipher.encrypt_ctr(&nonce_block, &mut ciphertext);
            }
            ChannelKey::None => {}
        }

        Some(ciphertext)
    }


    pub fn decrypt(&self, packet_id: u32, sender: u32, ciphertext: &[u8]) -> Option<Vec<u8, 256>> {
        if !self.key.is_encrypted() {
            return Vec::from_slice(ciphertext).ok();
        }


        let nonce = mesh_kdf::derive_nonce(packet_id, sender);


        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(ciphertext).ok()?;

        match &self.key {
            ChannelKey::Aes128(key) => {
                let cipher = Aes128::new(key);
                let mut nonce_block = [0u8; 16];
                nonce_block.copy_from_slice(&nonce);
                cipher.decrypt_ctr(&nonce_block, &mut plaintext);
            }
            ChannelKey::Aes256(key) => {
                let cipher = Aes256::new(key);
                let mut nonce_block = [0u8; 16];
                nonce_block.copy_from_slice(&nonce);
                cipher.decrypt_ctr(&nonce_block, &mut plaintext);
            }
            ChannelKey::None => {}
        }

        Some(plaintext)
    }


    pub fn hash(&self) -> u8 {
        let name = self.effective_name();
        channel_hash(&name, self.key.as_bytes())
    }


    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name).unwrap_or("")
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self::primary()
    }
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("index", &self.index)
            .field("name", &self.name_str())
            .field("key", &self.key)
            .field("modem_preset", &self.modem_preset)
            .finish()
    }
}


pub const MAX_CHANNELS: usize = 8;


pub struct ChannelSet {

    channels: [Option<Channel>; MAX_CHANNELS],
}

impl ChannelSet {

    pub fn new() -> Self {
        let mut channels = [None, None, None, None, None, None, None, None];
        channels[0] = Some(Channel::primary());
        Self { channels }
    }


    pub fn get(&self, index: u8) -> Option<&Channel> {
        self.channels.get(index as usize)?.as_ref()
    }


    pub fn get_mut(&mut self, index: u8) -> Option<&mut Channel> {
        self.channels.get_mut(index as usize)?.as_mut()
    }


    pub fn set(&mut self, index: u8, channel: Channel) {
        if (index as usize) < MAX_CHANNELS {
            self.channels[index as usize] = Some(channel);
        }
    }


    #[inline]
    pub fn primary(&self) -> Option<&Channel> {
        self.channels[0].as_ref()
    }


    #[inline]
    pub fn primary_mut(&mut self) -> Option<&mut Channel> {
        self.channels[0].as_mut()
    }


    pub fn primary_or_init(&mut self) -> &mut Channel {
        if self.channels[0].is_none() {
            self.channels[0] = Some(Channel::primary());
        }

        self.channels[0].as_mut().unwrap()
    }


    pub fn iter(&self) -> impl Iterator<Item = (u8, &Channel)> {
        self.channels
            .iter()
            .enumerate()
            .filter_map(|(i, ch)| ch.as_ref().map(|c| (i as u8, c)))
    }


    pub fn find_by_hash(&self, hash: u8) -> Option<&Channel> {
        for ch in self.channels.iter().flatten() {
            if ch.hash() == hash {
                return Some(ch);
            }
        }
        None
    }


    pub fn count(&self) -> usize {
        self.channels.iter().filter(|c| c.is_some()).count()
    }
}

impl Default for ChannelSet {
    fn default() -> Self {
        Self::new()
    }
}


const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


const BASE64_DECODE: [i8; 128] = {
    let mut table = [-1i8; 128];
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut i = 0;
    while i < 64 {
        table[chars[i] as usize] = i as i8;
        i += 1;
    }

    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table
};


pub fn base64_encode(data: &[u8], output: &mut [u8]) -> usize {
    let mut o = 0;
    let mut i = 0;

    while i + 2 < data.len() {
        if o + 4 > output.len() {
            break;
        }
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        output[o] = BASE64_CHARS[((n >> 18) & 0x3F) as usize];
        output[o + 1] = BASE64_CHARS[((n >> 12) & 0x3F) as usize];
        output[o + 2] = BASE64_CHARS[((n >> 6) & 0x3F) as usize];
        output[o + 3] = BASE64_CHARS[(n & 0x3F) as usize];
        i += 3;
        o += 4;
    }

    if i < data.len() && o + 4 <= output.len() {
        let remaining = data.len() - i;
        if remaining == 1 {
            let n = (data[i] as u32) << 16;
            output[o] = BASE64_CHARS[((n >> 18) & 0x3F) as usize];
            output[o + 1] = BASE64_CHARS[((n >> 12) & 0x3F) as usize];
            o += 2;
        } else if remaining == 2 {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            output[o] = BASE64_CHARS[((n >> 18) & 0x3F) as usize];
            output[o + 1] = BASE64_CHARS[((n >> 12) & 0x3F) as usize];
            output[o + 2] = BASE64_CHARS[((n >> 6) & 0x3F) as usize];
            o += 3;
        }
    }

    o
}


pub fn base64_decode(data: &[u8], output: &mut [u8]) -> usize {
    let mut o = 0;
    let mut i = 0;


    let data = if data.starts_with(b"https://meshtastic.org/e/#") {
        &data[26..]
    } else {
        data
    };

    while i + 3 < data.len() {
        if o + 3 > output.len() {
            break;
        }

        let b0 = BASE64_DECODE.get(data[i] as usize).copied().unwrap_or(-1);
        let b1 = BASE64_DECODE.get(data[i + 1] as usize).copied().unwrap_or(-1);
        let b2 = BASE64_DECODE.get(data[i + 2] as usize).copied().unwrap_or(-1);
        let b3 = BASE64_DECODE.get(data[i + 3] as usize).copied().unwrap_or(-1);

        if b0 < 0 || b1 < 0 {
            break;
        }

        let n = ((b0 as u32) << 18)
            | ((b1 as u32) << 12)
            | (if b2 >= 0 { (b2 as u32) << 6 } else { 0 })
            | (if b3 >= 0 { b3 as u32 } else { 0 });

        output[o] = (n >> 16) as u8;
        o += 1;

        if b2 >= 0 {
            output[o] = (n >> 8) as u8;
            o += 1;
        }

        if b3 >= 0 {
            output[o] = n as u8;
            o += 1;
        }

        i += 4;
    }


    if i + 1 < data.len() && o < output.len() {
        let b0 = BASE64_DECODE.get(data[i] as usize).copied().unwrap_or(-1);
        let b1 = BASE64_DECODE.get(data[i + 1] as usize).copied().unwrap_or(-1);

        if b0 >= 0 && b1 >= 0 {
            let n = ((b0 as u32) << 18) | ((b1 as u32) << 12);
            output[o] = (n >> 16) as u8;
            o += 1;

            if i + 2 < data.len() && o < output.len() {
                let b2 = BASE64_DECODE.get(data[i + 2] as usize).copied().unwrap_or(-1);
                if b2 >= 0 {
                    let n = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6);
                    output[o - 1] = (n >> 16) as u8;
                    output[o] = (n >> 8) as u8;
                    o += 1;
                }
            }
        }
    }

    o
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_creation() {
        let ch = Channel::new(0);
        assert_eq!(ch.index, 0);
        assert!(ch.key.is_encrypted());
    }

    #[test]
    fn test_channel_name_key_derivation() {
        let mut ch = Channel::new(0);
        ch.set_name("MyChannel");


        match &ch.key {
            ChannelKey::Aes256(k) => {

                let expected = Sha256::hash(b"MyChannel");
                assert_eq!(k, &expected);
            }
            _ => panic!("Expected AES-256 key"),
        }
    }

    #[test]
    fn test_match_default_preset_longfast() {
        assert!(match_default_preset_key(8).is_some());
        assert!(match_default_preset_key(0xFF).is_none());
    }

    #[test]
    fn test_encrypt_decrypt_multiblock_default_key() {
        let ch = Channel::primary();
        let plaintext = [0xABu8; 48];
        let packet_id = 0x11223344;
        let sender = 0x55667788;

        let ciphertext = ch.encrypt(packet_id, sender, &plaintext).unwrap();
        let decrypted = ch.decrypt(packet_id, sender, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext);
    }

    #[test]
    fn test_default_longfast_channel_hash() {
        let ch = Channel::primary();
        assert_eq!(ch.effective_name(), "LongFast");
        assert_eq!(ch.hash(), 8);
    }

    #[test]
    fn test_psk_shorthand_expansion() {
        let key = ChannelKey::from_psk(&[0x01]);
        assert!(matches!(key, ChannelKey::Aes128(_)));

        let key2 = ChannelKey::from_psk(&[0x03]);
        let bytes = key2.as_bytes();
        assert_eq!(bytes[15], 0x03);
    }

    #[test]
    fn test_channel_hash() {
        let mut ch = Channel::new(0);
        ch.set_name("Test");
        ch.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
        let expected = channel_hash(&ch.effective_name(), ch.key.as_bytes());
        assert_eq!(ch.hash(), expected);
    }

    #[test]
    fn test_channel_set() {
        let mut set = ChannelSet::new();
        assert_eq!(set.count(), 1);

        let mut secondary = Channel::new(1);
        secondary.set_name("Secondary");
        set.set(1, secondary);

        assert_eq!(set.count(), 2);
        assert_eq!(set.get(1).unwrap().name_str(), "Secondary");
    }

    #[test]
    fn test_modem_preset_params() {
        let params = ModemPreset::LongFast.lora_params();
        assert_eq!(params.spreading_factor, 11);
        assert_eq!(params.bandwidth, 125_000);
        assert_eq!(params.coding_rate, 8);
    }

    #[test]
    fn test_base64_encode() {
        let data = b"Hello";
        let mut output = [0u8; 16];
        let len = base64_encode(data, &mut output);
        assert_eq!(&output[..len], b"SGVsbG8");
    }

    #[test]
    fn test_base64_decode() {
        let data = b"SGVsbG8";
        let mut output = [0u8; 16];
        let len = base64_decode(data, &mut output);
        assert_eq!(&output[..len], b"Hello");
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let mut encoded = [0u8; 16];
        let enc_len = base64_encode(&original, &mut encoded);

        let mut decoded = [0u8; 16];
        let dec_len = base64_decode(&encoded[..enc_len], &mut decoded);

        assert_eq!(&decoded[..dec_len], &original);
    }

    #[test]
    fn test_airtime_calculation() {

        let airtime = ModemPreset::LongFast.airtime_ms(50);
        assert!(airtime > 100);
        assert!(airtime < 2000);
    }
}
