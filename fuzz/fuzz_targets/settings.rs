//! The settings file and a palette, both of which a person can edit by hand.
//!
//! A scale of 40 read from disk would draw one letter across the window and
//! leave no control large enough to change it back, so what comes out has to be
//! usable whatever went in.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(settings) = serde_json::from_str::<topgent_ui::settings::Settings>(text) {
        let style = settings.style();
        assert!(style.scale.is_finite() && style.scale > 0.0, "unusable scale from a file");
        assert!(style.pad(12.0) >= 1.0, "a spacing token collapsed to nothing");
        assert!(style.type_size(12.0) > 0.0, "type size collapsed to nothing");
    }
    if let Ok(palette) = serde_json::from_str::<topgent_ui::theme::Palette>(text) {
        // Every colour role must be printable, and the derived stripe must not
        // depend on a channel that is out of range.
        let _ = palette.grade("CRITICAL");
        let _ = palette.sensor("available");
        let stripe = palette.stripe();
        for channel in [stripe.r, stripe.g, stripe.b] {
            assert!(channel.is_finite(), "a derived colour is not a number");
        }
    }
});
