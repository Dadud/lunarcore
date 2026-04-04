#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbMode {
    CdcSerial,
    MassStorage,
    Composite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbDescriptorSet {
    pub vendor_id: u16,
    pub product_id: u16,
    pub max_power_ma: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbRuntime {
    pub cdc_enabled: bool,
    pub msc_enabled: bool,
    pub ble_coexistence: bool,
}

impl UsbRuntime {
    pub const fn nrf52_default() -> Self {
        Self {
            cdc_enabled: true,
            msc_enabled: true,
            ble_coexistence: true,
        }
    }

    pub fn preferred_mode(&self) -> UsbMode {
        match (self.cdc_enabled, self.msc_enabled) {
            (true, true) => UsbMode::Composite,
            (true, false) => UsbMode::CdcSerial,
            (false, true) => UsbMode::MassStorage,
            (false, false) => UsbMode::CdcSerial,
        }
    }
}

pub fn default_descriptors() -> UsbDescriptorSet {
    UsbDescriptorSet {
        vendor_id: 0x239A,
        product_id: 0x00C9,
        max_power_ma: 250,
    }
}

pub fn init_usb_runtime() -> UsbRuntime {
    #[cfg(feature = "nrf52")]
    {
        return UsbRuntime::nrf52_default();
    }

    UsbRuntime {
        cdc_enabled: false,
        msc_enabled: false,
        ble_coexistence: false,
    }
}

pub fn usb_log_transport() -> &'static str {
    #[cfg(feature = "nrf52")]
    {
        return "usb-cdc";
    }

    "uart"
}
