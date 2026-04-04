#[cfg(feature = "nrf52")]
pub mod nrf52;
#[cfg(feature = "stm32wl")]
pub mod stm32wl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardModel {
    Unknown,
    Esp32,
    Esp32S3,
    Nrf52,
    Stm32wl,
    Rak4631,
    Rak11310,
    NanoG1,
    NanoG1Explorer,
    NanoG2Ultra,
    StationG1,
    StationG2,
    Rak2560,
    Nrf52840Pca10059,
    Me25Ls014Y10Td,
    Rp2040FeatherRfm95,
    SenseLoRaRp2040,
    SenseLoRaS3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peripheral {
    LoRaCs,
    LoRaReset,
    LoRaBusy,
    LoRaDio1,
    SpiMosi,
    SpiMiso,
    SpiSck,
    I2cSda,
    I2cScl,
    BatteryAdc,
    Led,
    UsbDm,
    UsbDp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiConfig {
    pub sck: u32,
    pub mosi: u32,
    pub miso: u32,
    pub frequency_hz: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2cConfig {
    pub scl: u32,
    pub sda: u32,
    pub frequency_hz: u32,
}

pub trait Board {
    fn detect() -> Option<BoardModel>;
    fn gpio_for(peripheral: Peripheral) -> u32;
    fn spi_config() -> SpiConfig;
    fn i2c_config() -> I2cConfig;
    fn battery_adc_pin() -> u32;
    fn led_pin() -> Option<u32>;
    fn oled_present() -> bool;
}

pub fn detect_board_model() -> BoardModel {
    #[cfg(feature = "stm32wl")]
    {
        return BoardModel::Stm32wl;
    }

    #[cfg(feature = "nrf52")]
    {
        if let Some(board) = nrf52::Nrf52Board::detect() {
            return board;
        }
        return BoardModel::Nrf52;
    }

    #[cfg(feature = "v4")]
    {
        return BoardModel::Esp32S3;
    }

    #[allow(unreachable_code)]
    BoardModel::Esp32
}
