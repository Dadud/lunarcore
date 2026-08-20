use heapless::Vec;
use super::MAX_MESSAGE_SIZE;
use super::channel::Channel;
use super::protobuf;


pub const SESSION_PASSKEY_SIZE: usize = 8;

pub const PASSKEY_LIFETIME_MS: u32 = 300_000;

pub const PASSKEY_REGEN_MS: u32 = 150_000;


const ADMIN_GET_CHANNEL_REQUEST: u32 = 1;

const ADMIN_GET_CHANNEL_RESPONSE: u32 = 2;

const ADMIN_GET_OWNER_REQUEST: u32 = 3;

const ADMIN_GET_OWNER_RESPONSE: u32 = 4;

const ADMIN_GET_DEVICE_METADATA_REQUEST: u32 = 12;

const ADMIN_GET_DEVICE_METADATA_RESPONSE: u32 = 13;

const ADMIN_SET_CHANNEL: u32 = 33;

const ADMIN_SESSION_PASSKEY: u32 = 101;


const WIRE_VARINT: u8 = 0;

const WIRE_LEN: u8 = 2;


pub struct AdminSession {
    passkey: [u8; SESSION_PASSKEY_SIZE],
    generated_at_ms: u32,
}

impl AdminSession {
    pub const fn new() -> Self {
        Self {
            passkey: [0u8; SESSION_PASSKEY_SIZE],
            generated_at_ms: 0,
        }
    }

    pub fn ensure_fresh(&mut self, now_ms: u32) -> &[u8; SESSION_PASSKEY_SIZE] {
        if self.generated_at_ms == 0
            || now_ms.saturating_sub(self.generated_at_ms) >= PASSKEY_REGEN_MS
        {
            crate::rng::fill_random(&mut self.passkey);
            self.generated_at_ms = now_ms;
        }
        &self.passkey
    }

    pub fn validate(&self, provided: &[u8], now_ms: u32) -> bool {
        if provided.len() != SESSION_PASSKEY_SIZE {
            return false;
        }
        if self.generated_at_ms == 0
            || now_ms.saturating_sub(self.generated_at_ms) > PASSKEY_LIFETIME_MS
        {
            return false;
        }
        crate::crypto::constant_time_eq(provided, &self.passkey)
    }
}

impl Default for AdminSession {
    fn default() -> Self {
        Self::new()
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminKind {
    GetOwner,
    GetDeviceMetadata,
    GetChannel,
    SetChannel,
    StateChanging,
    ReadOnly,
    Unknown,
}


pub struct ParsedAdmin {
    pub kind: AdminKind,
    pub session_passkey: Option<[u8; SESSION_PASSKEY_SIZE]>,
    pub channel_index: u8,
    pub channel: Option<Channel>,
}


pub fn parse_admin_request(payload: &[u8]) -> ParsedAdmin {
    let mut kind = AdminKind::Unknown;
    let mut session_passkey = None;
    let mut channel_index = 0u8;
    let mut channel = None;
    let mut state_changing = false;

    let mut idx = 0;
    while idx < payload.len() {
        let (tag, consumed) = decode_varint(&payload[idx..]);
        if consumed == 0 {
            break;
        }
        idx += consumed;
        let field = (tag as u32) >> 3;
        let wire = (tag as u8) & 0x07;

        match wire {
            0 => {
                let (val, consumed) = decode_varint(&payload[idx..]);
                idx += consumed;
                match field {
                    ADMIN_GET_CHANNEL_REQUEST if val != 0 => {
                        kind = AdminKind::GetChannel;
                        channel_index = val.saturating_sub(1) as u8;
                    }
                    ADMIN_GET_OWNER_REQUEST if val != 0 => kind = AdminKind::GetOwner,
                    ADMIN_GET_DEVICE_METADATA_REQUEST if val != 0 => {
                        kind = AdminKind::GetDeviceMetadata
                    }
                    97 | 98 | 99 | 100 | 102 => state_changing = true,
                    _ => {}
                }
            }
            2 => {
                if idx >= payload.len() {
                    break;
                }
                let (len, consumed) = decode_varint(&payload[idx..]);
                idx += consumed;
                let len = len as usize;
                if idx + len > payload.len() {
                    break;
                }
                let bytes = &payload[idx..idx + len];
                if field == ADMIN_SESSION_PASSKEY && len == SESSION_PASSKEY_SIZE {
                    let mut key = [0u8; SESSION_PASSKEY_SIZE];
                    key.copy_from_slice(bytes);
                    session_passkey = Some(key);
                } else if field == ADMIN_SET_CHANNEL {
                    kind = AdminKind::SetChannel;
                    state_changing = true;
                    channel = protobuf::decode_channel(bytes);
                    if let Some(ref ch) = channel {
                        channel_index = ch.index;
                    }
                }
                idx += len;
            }
            5 => {
                if idx + 4 > payload.len() {
                    break;
                }
                idx += 4;
                if field == 95 || field == 102 {
                    state_changing = true;
                }
            }
            _ => break,
        }
    }

    if state_changing && kind != AdminKind::SetChannel {
        kind = AdminKind::StateChanging;
    } else if kind == AdminKind::Unknown {
        kind = AdminKind::ReadOnly;
    }

    ParsedAdmin {
        kind,
        session_passkey,
        channel_index,
        channel,
    }
}


pub fn build_admin_response(
    parsed: &ParsedAdmin,
    session: &mut AdminSession,
    now_ms: u32,
    node_id: u32,
    firmware_version: &str,
    channel: Option<&Channel>,
) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
    if parsed.kind == AdminKind::SetChannel || parsed.kind == AdminKind::StateChanging {
        let key = parsed.session_passkey.as_ref()?;
        if !session.validate(key, now_ms) {
            return None;
        }
    }

    let passkey = *session.ensure_fresh(now_ms);
    let mut admin = Vec::new();

    match parsed.kind {
        AdminKind::GetOwner => {
            let mut user = Vec::new();
            let id = format_node_id(node_id);
            write_bytes(1, id.as_bytes(), &mut user)?;
            write_bytes(2, b"LunarNode", &mut user)?;
            write_bytes(3, b"LNOD", &mut user)?;
            write_field_varint(5, 43, &mut user)?;
            write_field_varint(7, 4, &mut user)?;
            write_message(ADMIN_GET_OWNER_RESPONSE, &user, &mut admin)?;
        }
        AdminKind::GetDeviceMetadata => {
            let mut metadata = Vec::new();
            write_field_varint(1, 1, &mut metadata)?;
            write_bytes(2, firmware_version.as_bytes(), &mut metadata)?;
            write_field_varint(3, 1, &mut metadata)?;
            write_message(ADMIN_GET_DEVICE_METADATA_RESPONSE, &metadata, &mut admin)?;
        }
        AdminKind::GetChannel => {
            let ch = channel?;
            let encoded = protobuf::encode_channel(ch)?;
            write_message(ADMIN_GET_CHANNEL_RESPONSE, &encoded, &mut admin)?;
        }
        AdminKind::SetChannel => {
            let ch = channel?;
            let encoded = protobuf::encode_channel(ch)?;
            write_message(ADMIN_GET_CHANNEL_RESPONSE, &encoded, &mut admin)?;
        }
        AdminKind::ReadOnly | AdminKind::Unknown | AdminKind::StateChanging => {
            return None;
        }
    }

    write_bytes(ADMIN_SESSION_PASSKEY, &passkey, &mut admin)?;
    Some(admin)
}


pub fn apply_channel_update(parsed: &ParsedAdmin) -> Option<Channel> {
    parsed.channel.clone()
}


fn format_node_id(node_id: u32) -> heapless::String<16> {
    let mut s = heapless::String::new();
    let _ = s.push('!');
    for i in (0..8).rev() {
        let nibble = (node_id >> (i * 4)) & 0xF;
        let c = if nibble < 10 {
            b'0' + nibble as u8
        } else {
            b'a' + (nibble - 10) as u8
        };
        let _ = s.push(c as char);
    }
    s
}


fn decode_varint(data: &[u8]) -> (u64, usize) {
    let mut result = 0u64;
    let mut shift = 0;
    let mut consumed = 0;
    for &byte in data {
        consumed += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    (result, consumed)
}


fn write_tag(field: u32, wire_type: u8, buf: &mut Vec<u8, MAX_MESSAGE_SIZE>) -> Option<()> {
    write_varint(((field << 3) | wire_type as u32) as u64, buf)
}


fn write_field_varint(field: u32, value: u64, buf: &mut Vec<u8, MAX_MESSAGE_SIZE>) -> Option<()> {
    write_tag(field, WIRE_VARINT, buf)?;
    write_varint(value, buf)
}


fn write_varint(value: u64, buf: &mut Vec<u8, MAX_MESSAGE_SIZE>) -> Option<()> {
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte).ok()?;
            break;
        } else {
            buf.push(byte | 0x80).ok()?;
        }
    }
    Some(())
}


fn write_bytes(field: u32, data: &[u8], buf: &mut Vec<u8, MAX_MESSAGE_SIZE>) -> Option<()> {
    write_tag(field, WIRE_LEN, buf)?;
    write_varint(data.len() as u64, buf)?;
    buf.extend_from_slice(data).ok()?;
    Some(())
}

fn write_message(field: u32, inner: &[u8], buf: &mut Vec<u8, MAX_MESSAGE_SIZE>) -> Option<()> {
    write_tag(field, WIRE_LEN, buf)?;
    write_varint(inner.len() as u64, buf)?;
    buf.extend_from_slice(inner).ok()?;
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_session_regenerates() {
        let mut session = AdminSession::new();
        let key1 = *session.ensure_fresh(1000);
        let key2 = *session.ensure_fresh(1000);
        assert_eq!(key1, key2);

        let key3 = *session.ensure_fresh(1000 + PASSKEY_REGEN_MS);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_admin_session_validate() {
        let mut session = AdminSession::new();
        let key = *session.ensure_fresh(5000);
        assert!(session.validate(&key, 5000));
        assert!(!session.validate(&key, 5000 + PASSKEY_LIFETIME_MS + 1));
    }

    #[test]
    fn test_parse_get_device_metadata_request() {
        let payload = [0x60, 0x01];
        let req = parse_admin_request(&payload);
        assert_eq!(req.kind, AdminKind::GetDeviceMetadata);
    }

    #[test]
    fn test_parse_get_channel_request_is_one_based() {
        let payload = [0x08, 0x02];
        let req = parse_admin_request(&payload);
        assert_eq!(req.kind, AdminKind::GetChannel);
        assert_eq!(req.channel_index, 1);
    }

    #[test]
    fn test_set_channel_requires_passkey() {
        let mut session = AdminSession::new();
        let _ = session.ensure_fresh(1000);

        let mut ch = Channel::new(1);
        ch.set_name("Secondary");
        ch.set_key(&[0x02]);
        let encoded = protobuf::encode_channel(&ch).unwrap();

        let mut payload = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        write_message(ADMIN_SET_CHANNEL, &encoded, &mut payload).unwrap();
        let parsed = parse_admin_request(&payload);
        assert_eq!(parsed.kind, AdminKind::SetChannel);
        assert!(build_admin_response(
            &parsed,
            &mut session,
            1000,
            1,
            "1.1.0",
            Some(&ch)
        )
        .is_none());
    }
}
