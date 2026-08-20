use crate::crypto::ed25519::Ed25519;
use crate::crypto::sha256::Sha256;
use crate::crypto::x25519;

const KDF_SIGNING: &[u8] = b"LunarCore Signing v1";
const KDF_ENCRYPTION: &[u8] = b"LunarCore Encryption v1";

#[derive(Clone)]
pub struct DeviceIdentity {
    pub node_id: u32,
    pub mac_address: [u8; 6],
    pub hardware_serial: [u8; 8],
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
    pub encryption_public: [u8; 32],
    pub encryption_private: [u8; 32],
}

impl DeviceIdentity {
    pub fn from_hardware() -> Self {
        let mac_address = Self::read_mac_address();
        let hardware_serial = Self::read_hardware_serial();
        let (node_id, private_key, encryption_private) =
            Self::load_or_create_identity(&hardware_serial);
        let public_key = Ed25519::public_key(&private_key);
        let encryption_public = x25519::x25519_base(&encryption_private);

        Self {
            node_id,
            mac_address,
            hardware_serial,
            public_key,
            private_key,
            encryption_public,
            encryption_private,
        }
    }

    fn load_or_create_identity(
        hardware_serial: &[u8; 8],
    ) -> (u32, [u8; 32], [u8; 32]) {
        let nvs_result = unsafe {
            let mut handle: esp_idf_sys::nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_bytes_with_nul(b"lunarcore\0").unwrap();
            let err = esp_idf_sys::nvs_open(
                namespace.as_ptr(),
                esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
                &mut handle,
            );
            if err == esp_idf_sys::ESP_OK {
                Some(handle)
            } else {
                esp_idf_sys::nvs_flash_init();
                let err = esp_idf_sys::nvs_open(
                    namespace.as_ptr(),
                    esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
                    &mut handle,
                );
                if err == esp_idf_sys::ESP_OK {
                    Some(handle)
                } else {
                    None
                }
            }
        };

        if let Some(handle) = nvs_result {
            let mut node_id: u32 = 0;
            let mut signing_private = [0u8; 32];
            let mut encryption_private = [0u8; 32];
            let mut key_len: usize = 32;

            let node_id_key = core::ffi::CStr::from_bytes_with_nul(b"node_id\0").unwrap();
            let priv_key_key = core::ffi::CStr::from_bytes_with_nul(b"priv_key\0").unwrap();
            let enc_key_key = core::ffi::CStr::from_bytes_with_nul(b"enc_priv\0").unwrap();

            let has_node_id = unsafe {
                esp_idf_sys::nvs_get_u32(handle, node_id_key.as_ptr(), &mut node_id)
                    == esp_idf_sys::ESP_OK
            };

            let has_signing = unsafe {
                esp_idf_sys::nvs_get_blob(
                    handle,
                    priv_key_key.as_ptr(),
                    signing_private.as_mut_ptr() as *mut _,
                    &mut key_len,
                ) == esp_idf_sys::ESP_OK
                    && key_len == 32
            };

            let has_encryption = unsafe {
                key_len = 32;
                esp_idf_sys::nvs_get_blob(
                    handle,
                    enc_key_key.as_ptr(),
                    encryption_private.as_mut_ptr() as *mut _,
                    &mut key_len,
                ) == esp_idf_sys::ESP_OK
                    && key_len == 32
            };

            if has_node_id && has_signing {
                if !has_encryption {
                    encryption_private =
                        Self::derive_encryption_from_signing(&signing_private, hardware_serial);
                    unsafe {
                        esp_idf_sys::nvs_set_blob(
                            handle,
                            enc_key_key.as_ptr(),
                            encryption_private.as_ptr() as *const _,
                            32,
                        );
                        esp_idf_sys::nvs_commit(handle);
                    }
                    log::info!("Migrated legacy identity: derived separate encryption key");
                }

                log::info!("Loaded existing node identity from NVS");
                unsafe {
                    esp_idf_sys::nvs_close(handle);
                }
                return (node_id, signing_private, encryption_private);
            }

            log::info!("Creating new random node identity (privacy-first)");
            node_id = Self::generate_random_node_id();
            let seed = Self::generate_random_seed(hardware_serial);
            signing_private = Self::derive_signing_key(&seed);
            encryption_private = Self::derive_encryption_key(&seed);

            unsafe {
                esp_idf_sys::nvs_set_u32(handle, node_id_key.as_ptr(), node_id);
                esp_idf_sys::nvs_set_blob(
                    handle,
                    priv_key_key.as_ptr(),
                    signing_private.as_ptr() as *const _,
                    32,
                );
                esp_idf_sys::nvs_set_blob(
                    handle,
                    enc_key_key.as_ptr(),
                    encryption_private.as_ptr() as *const _,
                    32,
                );
                esp_idf_sys::nvs_commit(handle);
                esp_idf_sys::nvs_close(handle);
            }

            log::info!("Stored new identity in NVS");
            (node_id, signing_private, encryption_private)
        } else {
            log::warn!("NVS not available, using ephemeral identity");
            let node_id = Self::generate_random_node_id();
            let seed = Self::generate_random_seed(hardware_serial);
            (
                node_id,
                Self::derive_signing_key(&seed),
                Self::derive_encryption_key(&seed),
            )
        }
    }

    fn generate_random_node_id() -> u32 {
        let mut random_bytes = [0u8; 4];
        crate::rng::fill_random(&mut random_bytes);
        u32::from_le_bytes(random_bytes) | 0x8000_0000
    }

    fn generate_random_seed(hardware_serial: &[u8; 8]) -> [u8; 32] {
        let mut seed = [0u8; 32];
        crate::rng::fill_random(&mut seed);
        let mut mixed = [0u8; 40];
        mixed[..32].copy_from_slice(&seed);
        mixed[32..].copy_from_slice(hardware_serial);
        Sha256::hash(&mixed)
    }

    fn derive_key(seed: &[u8; 32], context: &[u8]) -> [u8; 32] {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(seed);
        let len = context.len().min(32);
        input[32..32 + len].copy_from_slice(&context[..len]);
        Sha256::hash(&input)
    }

    fn derive_signing_key(seed: &[u8; 32]) -> [u8; 32] {
        Self::derive_key(seed, KDF_SIGNING)
    }

    fn derive_encryption_key(seed: &[u8; 32]) -> [u8; 32] {
        let mut key = Self::derive_key(seed, KDF_ENCRYPTION);
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
        key
    }

    fn derive_encryption_from_signing(
        signing_private: &[u8; 32],
        hardware_serial: &[u8; 8],
    ) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(signing_private);
        let mut mixed = [0u8; 40];
        mixed[..32].copy_from_slice(&seed);
        mixed[32..].copy_from_slice(hardware_serial);
        let derived = Sha256::hash(&mixed);
        Self::derive_encryption_key(&derived)
    }

    pub fn factory_reset() -> Self {
        unsafe {
            let mut handle: esp_idf_sys::nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_bytes_with_nul(b"lunarcore\0").unwrap();
            if esp_idf_sys::nvs_open(
                namespace.as_ptr(),
                esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
                &mut handle,
            ) == esp_idf_sys::ESP_OK
            {
                esp_idf_sys::nvs_erase_all(handle);
                esp_idf_sys::nvs_commit(handle);
                esp_idf_sys::nvs_close(handle);
            }
        }

        log::info!("Factory reset: erased old identity, generating new one");
        Self::from_hardware()
    }

    fn read_mac_address() -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe {
            esp_idf_sys::esp_efuse_mac_get_default(mac.as_mut_ptr());
        }
        mac
    }

    fn read_hardware_serial() -> [u8; 8] {
        let mut serial = [0u8; 8];
        unsafe {
            let efuse_base: *const u32 = 0x6001_A044 as *const u32;
            let word0 = core::ptr::read_volatile(efuse_base);
            let word1 = core::ptr::read_volatile(efuse_base.add(1));
            serial[0..4].copy_from_slice(&word0.to_le_bytes());
            serial[4..8].copy_from_slice(&word1.to_le_bytes());
        }
        serial
    }

    pub fn x25519_pubkey(&self) -> [u8; 32] {
        self.encryption_public
    }
}

pub fn load_wifi_setting() -> bool {
    load_u8_setting(b"wifi\0", 0) != 0
}

pub fn save_wifi_setting(enabled: bool) {
    save_u8_setting(b"wifi\0", if enabled { 1 } else { 0 });
}

fn load_u8_setting(key: &[u8], default: u8) -> u8 {
    unsafe {
        let mut handle: esp_idf_sys::nvs_handle_t = 0;
        let namespace = core::ffi::CStr::from_bytes_with_nul(b"lunarcore\0").unwrap();
        if esp_idf_sys::nvs_open(
            namespace.as_ptr(),
            esp_idf_sys::nvs_open_mode_t_NVS_READONLY,
            &mut handle,
        ) != esp_idf_sys::ESP_OK
        {
            return default;
        }

        let key = core::ffi::CStr::from_bytes_with_nul(key).unwrap();
        let mut val = default;
        let result = esp_idf_sys::nvs_get_u8(handle, key.as_ptr(), &mut val);
        esp_idf_sys::nvs_close(handle);

        if result == esp_idf_sys::ESP_OK {
            val
        } else {
            default
        }
    }
}

fn save_u8_setting(key: &[u8], val: u8) {
    unsafe {
        let mut handle: esp_idf_sys::nvs_handle_t = 0;
        let namespace = core::ffi::CStr::from_bytes_with_nul(b"lunarcore\0").unwrap();
        if esp_idf_sys::nvs_open(
            namespace.as_ptr(),
            esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        ) != esp_idf_sys::ESP_OK
        {
            return;
        }

        let key = core::ffi::CStr::from_bytes_with_nul(key).unwrap();
        esp_idf_sys::nvs_set_u8(handle, key.as_ptr(), val);
        esp_idf_sys::nvs_commit(handle);
        esp_idf_sys::nvs_close(handle);
    }
}
