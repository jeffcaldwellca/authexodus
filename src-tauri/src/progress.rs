//! The lines sent on the `bw-progress` event while the Bitwarden tool is being prepared.
//!
//! THE UI SHOWS THESE EXACTLY AS THEY ARE WRITTEN HERE. They are whole, plain phrases in the
//! app's own voice; change one here and the screen changes with it. Nothing but a count of
//! megabytes is ever put into one.
//!
//! (The lines sent on the same event while decisions are applied are written in
//! `authexodus_core::bitwarden::apply`, and are shown as they are too.)

use authexodus_core::bitwarden::PrepareStage;

const MEGABYTE: u64 = 1024 * 1024;

pub const CHECKING: &str = "Checking the download";
pub const READY: &str = "Ready";

/// "Downloading… 12 of 44 MB", or "Downloading… 12 MB" when the size is not known. Megabytes
/// received are rounded down; the size is rounded up, so the first number never passes it.
pub fn downloading(received: u64, total: Option<u64>) -> String {
    let done = received / MEGABYTE;
    match total.filter(|total| *total > 0) {
        Some(total) => format!("Downloading… {done} of {} MB", total.div_ceil(MEGABYTE)),
        None => format!("Downloading… {done} MB"),
    }
}

/// The line for a stage of the preparation.
pub fn line(stage: PrepareStage) -> String {
    match stage {
        PrepareStage::Downloading { received, total } => downloading(received, total),
        PrepareStage::Checking => CHECKING.to_string(),
        PrepareStage::Ready => READY.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_are_plain_and_count_megabytes() {
        assert_eq!(
            downloading(12 * MEGABYTE + 5, Some(43 * MEGABYTE + 700_000)),
            "Downloading… 12 of 44 MB"
        );
        assert_eq!(
            downloading(0, Some(44 * MEGABYTE)),
            "Downloading… 0 of 44 MB"
        );
        assert_eq!(
            downloading(44 * MEGABYTE, Some(44 * MEGABYTE)),
            "Downloading… 44 of 44 MB"
        );
        assert_eq!(downloading(3 * MEGABYTE, None), "Downloading… 3 MB");
        assert_eq!(downloading(3 * MEGABYTE, Some(0)), "Downloading… 3 MB");
        assert_eq!(line(PrepareStage::Checking), "Checking the download");
        assert_eq!(line(PrepareStage::Ready), "Ready");
        assert_eq!(
            line(PrepareStage::Downloading {
                received: MEGABYTE,
                total: Some(2 * MEGABYTE)
            }),
            "Downloading… 1 of 2 MB"
        );
    }
}
