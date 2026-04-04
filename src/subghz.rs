use heapless::Vec;

use crate::radio::{ModemConfig, Packet, Radio, RadioError};

pub struct SubGhzRadio {
    modem: ModemConfig,
}

impl SubGhzRadio {
    pub fn new() -> Self {
        Self { modem: ModemConfig::default() }
    }
}

impl Default for SubGhzRadio {
    fn default() -> Self {
        Self::new()
    }
}

impl Radio for SubGhzRadio {
    fn init(&mut self) -> Result<(), RadioError> {
        Ok(())
    }

    fn set_frequency(&mut self, freq_hz: u32) -> Result<(), RadioError> {
        self.modem.frequency_hz = freq_hz;
        Ok(())
    }

    fn set_tx_power(&mut self, power_dbm: i8) -> Result<(), RadioError> {
        self.modem.tx_power_dbm = power_dbm;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), RadioError> {
        if data.len() > 255 {
            return Err(RadioError::BufferOverflow);
        }
        Ok(())
    }

    fn receive(&mut self, _timeout_ms: u32) -> Result<Packet, RadioError> {
        Ok(Packet { payload: Vec::new(), rssi: -100, snr: 0 })
    }

    fn set_modem(&mut self, config: ModemConfig) -> Result<(), RadioError> {
        self.modem = config;
        Ok(())
    }
}
