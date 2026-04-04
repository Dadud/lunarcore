use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal::spi::SpiDevice;
use heapless::Vec;

use crate::radio::{ModemConfig, Packet, Radio, RadioError};

pub const SX1276_MIN_FREQUENCY_HZ: u32 = 137_000_000;
pub const SX1276_MAX_FREQUENCY_HZ: u32 = 1_020_000_000;
pub const SX1276_MAX_TX_POWER_DBM: i8 = 20;

pub struct Sx1276<SPI, NSS, RESET, DIO0, DIO1> {
    spi: SPI,
    nss: NSS,
    reset: RESET,
    dio0: DIO0,
    dio1: DIO1,
    modem: ModemConfig,
}

impl<SPI, NSS, RESET, DIO0, DIO1> Sx1276<SPI, NSS, RESET, DIO0, DIO1> {
    pub fn new(spi: SPI, nss: NSS, reset: RESET, dio0: DIO0, dio1: DIO1) -> Self {
        Self {
            spi,
            nss,
            reset,
            dio0,
            dio1,
            modem: ModemConfig::default(),
        }
    }

    pub fn supports_frequency(freq_hz: u32) -> bool {
        (SX1276_MIN_FREQUENCY_HZ..=SX1276_MAX_FREQUENCY_HZ).contains(&freq_hz)
    }

    pub fn supports_spreading_factor(sf: u8) -> bool {
        (7..=12).contains(&sf)
    }

    pub fn supports_tx_power(power_dbm: i8) -> bool {
        (2..=SX1276_MAX_TX_POWER_DBM).contains(&power_dbm)
    }

    pub fn dio_interrupt_active(&self) -> bool
    where
        DIO0: InputPin,
        DIO1: InputPin,
    {
        self.dio0.is_high().unwrap_or(false) || self.dio1.is_high().unwrap_or(false)
    }

    pub fn cad_detected(&self) -> bool
    where
        DIO1: InputPin,
    {
        self.dio1.is_high().unwrap_or(false)
    }
}

impl<SPI, NSS, RESET, DIO0, DIO1, E> Radio for Sx1276<SPI, NSS, RESET, DIO0, DIO1>
where
    SPI: SpiDevice<Error = E>,
    NSS: OutputPin,
    RESET: OutputPin,
    DIO0: InputPin,
    DIO1: InputPin,
{
    fn init(&mut self) -> Result<(), RadioError> {
        let _ = self.reset.set_low();
        let _ = self.reset.set_high();
        self.set_modem(self.modem)
    }

    fn set_frequency(&mut self, freq_hz: u32) -> Result<(), RadioError> {
        if !Self::supports_frequency(freq_hz) {
            return Err(RadioError::InvalidConfig);
        }
        self.modem.frequency_hz = freq_hz;
        let _ = self.nss.set_low();
        let _ = self.spi.write(&[0x06, ((freq_hz >> 16) & 0xFF) as u8, ((freq_hz >> 8) & 0xFF) as u8, (freq_hz & 0xFF) as u8]).map_err(|_| RadioError::Spi)?;
        let _ = self.nss.set_high();
        Ok(())
    }

    fn set_tx_power(&mut self, power_dbm: i8) -> Result<(), RadioError> {
        if !Self::supports_tx_power(power_dbm) {
            return Err(RadioError::InvalidConfig);
        }
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
        let payload = Vec::new();
        Ok(Packet { payload, rssi: -120, snr: 0 })
    }

    fn set_modem(&mut self, config: ModemConfig) -> Result<(), RadioError> {
        if !Self::supports_frequency(config.frequency_hz)
            || !Self::supports_spreading_factor(config.spreading_factor)
            || !Self::supports_tx_power(config.tx_power_dbm)
        {
            return Err(RadioError::InvalidConfig);
        }
        self.modem = config;
        Ok(())
    }
}
