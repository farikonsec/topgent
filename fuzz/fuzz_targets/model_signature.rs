//! The model reader, which parses files an agent wrote.
//!
//! A config file, a session transcript and a key-value file all belong to the
//! thing being watched. An agent that wanted to poison a report, mislead an
//! operator, or crash the monitor would do it here, so every extractor is
//! fuzzed against arbitrary bytes and the result is checked, not just accepted.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(signatures) = topgent_collect::model::builtin() else {
        return;
    };
    for kind in [
        topgent_collect::model::SourceKind::Json,
        topgent_collect::model::SourceKind::Jsonl,
        topgent_collect::model::SourceKind::Keyvalue,
    ] {
        // The key is drawn from the input too, so a hostile file cannot rely on
        // the reader only ever looking for `model`.
        for key in ["model", "GOOSE_MODEL", text.get(..8).unwrap_or("model")] {
            if let Some(found) = topgent_collect::model::extract(kind, text, key)
                && topgent_collect::model::admissible(signatures, &found)
            {
                // Anything the gate admits is going into a report, a table and
                // an export. These are the properties that stop it carrying
                // something else there.
                let trimmed = found.trim();
                assert!(!trimmed.is_empty(), "an empty model was admitted");
                assert!(
                    trimmed.len() <= signatures.max_model_bytes,
                    "an oversized model was admitted: {} bytes",
                    trimmed.len()
                );
                assert!(
                    !trimmed.contains('\n') && !trimmed.contains('\r'),
                    "a multi-line model was admitted"
                );
                assert!(
                    !trimmed.chars().any(char::is_control),
                    "a control character was admitted"
                );
                // The provider is derived from the model string, so a hostile
                // string must not be able to invent one.
                let provider =
                    topgent_collect::model::provider_of(signatures, trimmed, "");
                assert!(
                    provider.is_empty()
                        || signatures
                            .providers
                            .iter()
                            .any(|rule| rule.provider == provider),
                    "provider {provider:?} is not one this build knows"
                );
            }
        }
    }
});
