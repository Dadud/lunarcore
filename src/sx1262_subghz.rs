use crate::sx1262::{RadioConfig, RadioError, RadioState};

pub const SUBGHZ_MIN_FREQUENCY: u32 = 150_000_000;
pub const SUBGHZ_MAX_FREQUENCY: u32 = 960_000_000;

#[derive(Debug, Clone)]
pub struct SubGhzConfig {
    pub radio: RadioConfig,
    pub fallback_mode: RadioState,
    pub uses_internal_rf_path: bool,
}

impl Default for SubGhzConfig {
    fn default() -> Self {
        Self {
            radio: RadioConfig::default(),
            fallback_mode: RadioState::Standby,
            uses_internal_rf_path: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubGhzInterface {
    InternalSubGhz,
}

#[derive(Debug, Clone)]
pub struct PacketStatus {
    pub rssi_dbm: i16,
    pub snr_db: i8,
}

pub struct SubGhzRadio {
    pub config: SubGhzConfig,
    pub state: RadioState,
    pub interface: SubGhzInterface,
    rx_buffer: heapless::Vec<u8, 256>,
    tx_buffer: heapless::Vec<u8, 256>,
    pub last_packet_status: Option<PacketStatus>,
}

impl SubGhzRadio {
    pub fn new() -> Self {
        Self {
            config: SubGhzConfig::default(),
            state: RadioState::Sleep,
            interface: SubGhzInterface::InternalSubGhz,
            rx_buffer: heapless::Vec::new(),
            tx_buffer: heapless::Vec::new(),
            last_packet_status: None,
        }
    }

    pub fn init(&mut self) -> Result<(), RadioError> {
        self.validate_frequency(self.config.radio.frequency)?;
        self.state = RadioState::Standby;
        Ok(())
    }

    pub fn configure(&mut self, config: &SubGhzConfig) -> Result<(), RadioError> {
        self.validate_frequency(config.radio.frequency)?;
        self.config = config.clone();
        self.state = RadioState::Standby;
        Ok(())
    }

    pub fn set_frequency(&mut self, frequency: u32) -> Result<(), RadioError> {
        self.validate_frequency(frequency)?;
        self.config.radio.frequency = frequency;
        Ok(())
    }

    pub fn transmit(&mut self, payload: &[u8]) -> Result<(), RadioError> {
        if payload.len() > 255 {
            return Err(RadioError::BufferOverflow);
        }

        self.tx_buffer.clear();
        self.tx_buffer
            .extend_from_slice(payload)
            .map_err(|_| RadioError::BufferOverflow)?;
        self.state = RadioState::Tx;
        self.state = self.config.fallback_mode;
        Ok(())
    }

    pub fn inject_received(&mut self, payload: &[u8], rssi_dbm: i16, snr_db: i8) -> Result<(), RadioError> {
        if payload.len() > 255 {
            return Err(RadioError::BufferOverflow);
        }

        self.rx_buffer.clear();
        self.rx_buffer
            .extend_from_slice(payload)
            .map_err(|_| RadioError::BufferOverflow)?;
        self.last_packet_status = Some(PacketStatus { rssi_dbm, snr_db });
        self.state = RadioState::Rx;
        Ok(())
    }

    pub fn read_packet(&mut self) -> Option<(heapless::Vec<u8, 256>, PacketStatus)> {
        let mut packet = heapless::Vec::new();
        packet.extend_from_slice(&self.rx_buffer).ok()?;
        let status = self.last_packet_status.clone()?;
        self.rx_buffer.clear();
        self.last_packet_status = None;
        self.state = self.config.fallback_mode;
        Some((packet, status))
    }

    pub fn start_rx(&mut self) {
        self.state = RadioState::Rx;
    }

    pub fn sleep(&mut self) {
        self.state = RadioState::Sleep;
    }

    pub fn state(&self) -> RadioState {
        self.state
    }

    fn validate_frequency(&self, frequency: u32) -> Result<(), RadioError> {
        if !(SUBGHZ_MIN_FREQUENCY..=SUBGHZ_MAX_FREQUENCY).contains(&frequency) {
            return Err(RadioError::InvalidConfig);
        }
        Ok(())
    }
}

impl Default for SubGhzRadio {
    fn default() -> Self {
        Self::new()
    }
}
