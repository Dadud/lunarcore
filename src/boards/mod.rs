#[cfg(feature = "nrf52")]
pub mod nrf52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardModel {
    Unknown,
    Esp32,
    Esp32S3,
    Nrf52,
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
    RNodeV1,
    RNodeV2,
    AdafruitFeatherEsp32LoRa,
    GenericEsp32LoRa,
    SeeedStudioLoRaRadio,
}

pub fn detect_board_model() -> BoardModel {
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

    BoardModel::Esp32
}
