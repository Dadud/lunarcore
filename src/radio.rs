use heapless::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioModulation {
    LoRa,
    Flrc,
    Gfsk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModemConfig {
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power_dbm: i8,
    pub sync_word: u8,
    pub preamble_length: u16,
    pub crc_enabled: bool,
    pub implicit_header: bool,
    pub low_data_rate_optimize: bool,
    pub modulation: RadioModulation,
}

impl Default for ModemConfig {
    fn default() -> Self {
        Self {
            frequency_hz: 915_000_000,
            bandwidth_hz: 125_000,
            spreading_factor: 9,
            coding_rate: 5,
            tx_power_dbm: 14,
            sync_word: 0x12,
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            low_data_rate_optimize: false,
            modulation: RadioModulation::LoRa,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub payload: Vec<u8, 256>,
    pub rssi: i16,
    pub snr: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioError {
    Spi,
    BusyTimeout,
    InvalidConfig,
    TxTimeout,
    RxTimeout,
    CrcError,
    BufferOverflow,
    Unsupported,
}

pub trait Radio {
    fn init(&mut self) -> Result<(), RadioError>;
    fn set_frequency(&mut self, freq_hz: u32) -> Result<(), RadioError>;
    fn set_tx_power(&mut self, power_dbm: i8) -> Result<(), RadioError>;
    fn send(&mut self, data: &[u8]) -> Result<(), RadioError>;
    fn receive(&mut self, timeout_ms: u32) -> Result<Packet, RadioError>;
    fn set_modem(&mut self, config: ModemConfig) -> Result<(), RadioError>;
}
