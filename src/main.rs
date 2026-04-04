mod boards;
mod usb;

use boards::BoardModel;

fn detect_board() -> BoardModel {
    #[cfg(feature = "v4")]
    {
        return BoardModel::Esp32S3;
    }

    #[cfg(feature = "nrf52")]
    {
        return BoardModel::Nrf52;
    }

    boards::detect_board_model()
}

#[cfg(feature = "v4")]
include!("main_v4.rs");

#[cfg(not(feature = "v4"))]
include!("main_v3.rs");
