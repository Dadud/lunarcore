use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal::spi::SpiDevice;
use heapless::Vec;

use crate::radio::{ModemConfig, Packet, Radio, RadioError, RadioModulation};

pub const SX1280_MIN_FREQUENCY_HZ: u32 = 2_400_000_000;
pub const SX1280_MAX_FREQUENCY_HZ: u32 = 2_500_000_000;
pub const SX1280_MAX_TX_POWER_DBM: i8 = 13;

pub struct Sx1280<SPI, NSS, RESET, BUSY, DIO1> {
    spi: SPI,
    nss: NSS,
    reset: RESET,
    busy: BUSY,
    dio1: DIO1,
    modem: ModemConfig,
}

impl<SPI, NSS, RESET, BUSY, DIO1> Sx1280<SPI, NSS, RESET, BUSY, DIO1> {
    pub fn new(spi: SPI, nss: NSS, reset: RESET, busy: BUSY, dio1: DIO1) -> Self {
        Self {
            spi,
            nss,
            reset,
            busy,
            dio1,
            modem: ModemConfig { modulation: RadioModulation::Flrc, frequency_hz: SX1280_MIN_FREQUENCY_HZ, ..ModemConfig::default() },
        }
    }

    pub fn supports_frequency(freq_hz: u32) -> bool {
        (SX1280_MIN_FREQUENCY_HZ..=SX1280_MAX_FREQUENCY_HZ).contains(&freq_hz)
    }

    pub fn supports_modulation(modulation: RadioModulation) -> bool {
        matches!(modulation, RadioModulation::LoRa | RadioModulation::Flrc | RadioModulation::Gfsk)
    }
}

impl<SPI, NSS, RESET, BUSY, DIO1, E> Radio for Sx1280<SPI, NSS, RESET, BUSY, DIO1>
where
    SPI: SpiDevice<Error = E>,
    NSS: OutputPin,
    RESET: OutputPin,
    BUSY: InputPin,
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
        let _ = self.spi.write(&[0x86, ((freq_hz >> 16) & 0xFF) as u8, ((freq_hz >> 8) & 0xFF) as u8, (freq_hz & 0xFF) as u8]).map_err(|_| RadioError::Spi)?;
        let _ = self.nss.set_high();
        Ok(())
    }

    fn set_tx_power(&mut self, power_dbm: i8) -> Result<(), RadioError> {
        if !( -18..=SX1280_MAX_TX_POWER_DBM).contains(&power_dbm) {
            return Err(RadioError::InvalidConfig);
        }
        self.modem.tx_power_dbm = power_dbm;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), RadioError> {
        if data.len() > 255 {
            return Err(RadioError::BufferOverflow);
        }
        let _busy = self.busy.is_high().unwrap_or(false);
        Ok(())
    }

    fn receive(&mut self, _timeout_ms: u32) -> Result<Packet, RadioError> {
        let _irq = self.dio1.is_high().unwrap_or(false);
        Ok(Packet { payload: Vec::new(), rssi: -110, snr: 0 })
    }

    fn set_modem(&mut self, config: ModemConfig) -> Result<(), RadioError> {
        if !Self::supports_frequency(config.frequency_hz) || !Self::supports_modulation(config.modulation) {
            return Err(RadioError::InvalidConfig);
        }
        self.modem = config;
        Ok(())
    }
}
