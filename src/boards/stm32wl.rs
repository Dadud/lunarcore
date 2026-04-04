use crate::power::{PowerManager as PowerControl, Stm32wlPower};
use crate::sx1262_subghz::{SubGhzConfig, SubGhzRadio};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stm32wlVariant {
    Rak3172,
    WioE5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpioPin {
    pub port: char,
    pub pin: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiMapping {
    pub sck: GpioPin,
    pub miso: Option<GpioPin>,
    pub mosi: Option<GpioPin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2cMapping {
    pub scl: GpioPin,
    pub sda: GpioPin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcConfig {
    pub clock_source: &'static str,
    pub wakeup_resolution_hz: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BorConfig {
    pub enabled: bool,
    pub threshold_mv: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stm32wlBoardConfig {
    pub variant: Stm32wlVariant,
    pub led: GpioPin,
    pub boot: Option<GpioPin>,
    pub uart_tx: GpioPin,
    pub uart_rx: GpioPin,
    pub debug_spi: Option<SpiMapping>,
    pub i2c: Option<I2cMapping>,
    pub rtc: RtcConfig,
    pub bor: BorConfig,
    pub stop2_supported: bool,
}

impl Stm32wlBoardConfig {
    pub const fn rak3172() -> Self {
        Self {
            variant: Stm32wlVariant::Rak3172,
            led: GpioPin { port: 'B', pin: 5 },
            boot: Some(GpioPin { port: 'A', pin: 14 }),
            uart_tx: GpioPin { port: 'A', pin: 2 },
            uart_rx: GpioPin { port: 'A', pin: 3 },
            debug_spi: None,
            i2c: Some(I2cMapping {
                scl: GpioPin { port: 'B', pin: 15 },
                sda: GpioPin { port: 'A', pin: 15 },
            }),
            rtc: RtcConfig {
                clock_source: "LSE",
                wakeup_resolution_hz: 1,
            },
            bor: BorConfig {
                enabled: true,
                threshold_mv: 1800,
            },
            stop2_supported: true,
        }
    }

    pub const fn wio_e5() -> Self {
        Self {
            variant: Stm32wlVariant::WioE5,
            led: GpioPin { port: 'B', pin: 5 },
            boot: Some(GpioPin { port: 'A', pin: 15 }),
            uart_tx: GpioPin { port: 'A', pin: 2 },
            uart_rx: GpioPin { port: 'A', pin: 3 },
            debug_spi: Some(SpiMapping {
                sck: GpioPin { port: 'A', pin: 5 },
                miso: Some(GpioPin { port: 'A', pin: 6 }),
                mosi: Some(GpioPin { port: 'A', pin: 7 }),
            }),
            i2c: Some(I2cMapping {
                scl: GpioPin { port: 'B', pin: 13 },
                sda: GpioPin { port: 'B', pin: 14 },
            }),
            rtc: RtcConfig {
                clock_source: "LSE",
                wakeup_resolution_hz: 1,
            },
            bor: BorConfig {
                enabled: true,
                threshold_mv: 1800,
            },
            stop2_supported: true,
        }
    }
}

pub struct Stm32wlBoard {
    pub config: Stm32wlBoardConfig,
    pub radio: SubGhzRadio,
    pub power: Stm32wlPower,
}

impl Stm32wlBoard {
    pub fn new(config: Stm32wlBoardConfig) -> Self {
        let mut radio = SubGhzRadio::new();
        let _ = radio.configure(&SubGhzConfig::default());

        Self {
            config,
            radio,
            power: Stm32wlPower::default(),
        }
    }

    pub fn enter_stop2(&self, duration_ms: u32) {
        Stm32wlPower::sleep(duration_ms);
    }

    pub fn configure_bor(&mut self, threshold_mv: u16) {
        self.power.bor_threshold_mv = threshold_mv;
    }

    pub fn schedule_wakeup(&mut self, duration_ms: u32) {
        self.power.last_sleep_ms = duration_ms;
    }
}
