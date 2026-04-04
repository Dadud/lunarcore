pub const MIN_DEEP_SLEEP_US: u64 = 1_000;
pub const MAX_DEEP_SLEEP_US: u64 = 86_400_000_000;
pub const DEFAULT_LIGHT_SLEEP_MS: u32 = 100;
pub const LOW_BATTERY_THRESHOLD_MV: u32 = 3400;
pub const CRITICAL_BATTERY_THRESHOLD_MV: u32 = 3200;

pub trait PowerManager {
    fn sleep(duration_ms: u32);
    fn deep_sleep();
    fn wake_from_rtc();
    fn battery_voltage() -> f32;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Esp32Power;

impl PowerManager for Esp32Power {
    fn sleep(duration_ms: u32) {
        #[cfg(any(target_arch = "xtensa", target_os = "espidf"))]
        unsafe {
            let duration_us = (duration_ms.max(1) as u64) * 1000;
            esp_idf_sys::esp_sleep_enable_timer_wakeup(duration_us);
            let _ = esp_idf_sys::esp_light_sleep_start();
        }

        #[cfg(not(any(target_arch = "xtensa", target_os = "espidf")))]
        {
            let _ = duration_ms;
        }
    }

    fn deep_sleep() {
        #[cfg(any(target_arch = "xtensa", target_os = "espidf"))]
        unsafe {
            esp_idf_sys::esp_deep_sleep_start();
        }
    }

    fn wake_from_rtc() {}

    fn battery_voltage() -> f32 {
        3.7
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Nrf52Power;

impl PowerManager for Nrf52Power {
    fn sleep(duration_ms: u32) {
        let _ = duration_ms;
    }

    fn deep_sleep() {
        // nRF52 system OFF placeholder until HAL wiring lands.
    }

    fn wake_from_rtc() {}

    fn battery_voltage() -> f32 {
        3.6
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Stm32wlPower {
    pub last_sleep_ms: u32,
    pub bor_threshold_mv: u16,
    pub rtc_wakeup_enabled: bool,
}

impl Default for Stm32wlPower {
    fn default() -> Self {
        Self {
            last_sleep_ms: DEFAULT_LIGHT_SLEEP_MS,
            bor_threshold_mv: 1800,
            rtc_wakeup_enabled: true,
        }
    }
}

impl PowerManager for Stm32wlPower {
    fn sleep(duration_ms: u32) {
        let _ = duration_ms;
        // STM32WL STOP2 placeholder: RTC wakeup should be armed before WFI/WFE.
    }

    fn deep_sleep() {
        // STM32WL deepest low-power profile placeholder.
    }

    fn wake_from_rtc() {
        // RTC wakeup handling placeholder.
    }

    fn battery_voltage() -> f32 {
        3.5
    }
}

pub fn is_battery_low(voltage_mv: u32) -> bool {
    voltage_mv < LOW_BATTERY_THRESHOLD_MV
}

pub fn is_battery_critical(voltage_mv: u32) -> bool {
    voltage_mv < CRITICAL_BATTERY_THRESHOLD_MV
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_work() {
        assert!(!is_battery_low(3600));
        assert!(is_battery_low(3300));
        assert!(is_battery_critical(3100));
    }
}
