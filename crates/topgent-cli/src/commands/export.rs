//! `topgent export` — the AI bill of materials, in `CycloneDX` JSON or HTML.

use crate::output::option_value;

pub(crate) fn export_command(args: &[String]) -> i32 {
    if args.get(1).map(String::as_str) != Some("cyclonedx") {
        eprintln!("topgent export cyclonedx [--format json|html] [--output PATH]");
        return 2;
    }
    let document = topgent_report::cyclonedx_scan();
    if let Some(error) = document.get("error").and_then(serde_json::Value::as_str) {
        eprintln!("topgent export: {error}");
        return 2;
    }
    let format = option_value(args, "--format").unwrap_or("json");
    let rendered = match format {
        "json" => {
            if let Ok(rendered) = serde_json::to_string_pretty(&document) {
                rendered
            } else {
                eprintln!("topgent export: could not serialize CycloneDX document");
                return 2;
            }
        }
        "html" => match topgent_export::cyclonedx_html(&document) {
            Ok(rendered) => rendered,
            Err(error) => {
                eprintln!("topgent export: {error}");
                return 2;
            }
        },
        _ => {
            eprintln!("topgent export: --format must be json or html");
            return 2;
        }
    };
    if let Some(path) = option_value(args, "--output") {
        let path = std::path::Path::new(path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            eprintln!("topgent export: {error}");
            return 2;
        }
        if let Err(error) = std::fs::write(path, format!("{rendered}\n")) {
            eprintln!("topgent export: {error}");
            return 2;
        }
        eprintln!(
            "Wrote CycloneDX 1.6 AI-BOM ({format}) to {}",
            path.display()
        );
    } else {
        println!("{rendered}");
    }
    0
}
