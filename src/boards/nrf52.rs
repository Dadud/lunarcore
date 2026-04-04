use super::{Board, BoardModel, I2cConfig, Peripheral, SpiConfig};

pub struct Nrf52Board;

impl Nrf52Board {
    pub const GPIO_SPI_SCK: u32 = 14;
    pub const GPIO_SPI_MOSI: u32 = 13;
    pub const GPIO_SPI_MISO: u32 = 15;
    pub const GPIO_I2C_SCL: u32 = 27;
    pub const GPIO_I2C_SDA: u32 = 26;
    pub const GPIO_LORA_CS: u32 = 5;
    pub const GPIO_LORA_RST: u32 = 6;
    pub const GPIO_LORA_BUSY: u32 = 7;
    pub const GPIO_LORA_DIO1: u32 = 8;
    pub const GPIO_BATTERY_ADC: u32 = 4;
    pub const GPIO_LED: u32 = 19;
    pub const GPIO_USB_DM: u32 = 24;
    pub const GPIO_USB_DP: u32 = 25;

    pub fn twim_config() -> I2cConfig {
        I2cConfig {
            scl: Self::GPIO_I2C_SCL,
            sda: Self::GPIO_I2C_SDA,
            frequency_hz: 400_000,
        }
    }

    pub fn spim_config() -> SpiConfig {
        SpiConfig {
            sck: Self::GPIO_SPI_SCK,
            mosi: Self::GPIO_SPI_MOSI,
            miso: Self::GPIO_SPI_MISO,
            frequency_hz: 8_000_000,
        }
    }

    pub fn saadc_channel() -> u32 {
        Self::GPIO_BATTERY_ADC
    }

    pub fn native_usb_enabled() -> bool {
        true
    }

    pub fn board_candidates() -> &'static [BoardModel] {
        &[
            BoardModel::Rak4631,
            BoardModel::Rak11310,
            BoardModel::StationG1,
            BoardModel::StationG2,
            BoardModel::NanoG1,
            BoardModel::NanoG1Explorer,
            BoardModel::NanoG2Ultra,
            BoardModel::Nrf52840Pca10059,
        ]
    }
}

impl Board for Nrf52Board {
    fn detect() -> Option<BoardModel> {
        #[cfg(feature = "nrf52")]
        {
            return Some(BoardModel::Rak4631);
        }

        #[allow(unreachable_code)]
        None
    }

    fn gpio_for(peripheral: Peripheral) -> u32 {
        match peripheral {
            Peripheral::LoRaCs => Self::GPIO_LORA_CS,
            Peripheral::LoRaReset => Self::GPIO_LORA_RST,
            Peripheral::LoRaBusy => Self::GPIO_LORA_BUSY,
            Peripheral::LoRaDio1 => Self::GPIO_LORA_DIO1,
            Peripheral::SpiMosi => Self::GPIO_SPI_MOSI,
            Peripheral::SpiMiso => Self::GPIO_SPI_MISO,
            Peripheral::SpiSck => Self::GPIO_SPI_SCK,
            Peripheral::I2cSda => Self::GPIO_I2C_SDA,
            Peripheral::I2cScl => Self::GPIO_I2C_SCL,
            Peripheral::BatteryAdc => Self::GPIO_BATTERY_ADC,
            Peripheral::Led => Self::GPIO_LED,
            Peripheral::UsbDm => Self::GPIO_USB_DM,
            Peripheral::UsbDp => Self::GPIO_USB_DP,
        }
    }

    fn spi_config() -> SpiConfig {
        Self::spim_config()
    }

    fn i2c_config() -> I2cConfig {
        Self::twim_config()
    }

    fn battery_adc_pin() -> u32 {
        Self::saadc_channel()
    }

    fn led_pin() -> Option<u32> {
        Some(Self::GPIO_LED)
    }

    fn oled_present() -> bool {
        true
    }
}
