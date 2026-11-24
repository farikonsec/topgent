//! Compile the application icon into the desktop binary.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::BufReader;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    icon();
}

/// Decode the application icon once and hand the interface raw pixels.
fn icon() {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the crate sits two levels under the workspace root")
        .join("assets");
    let png = assets.join("icon.png");
    println!("cargo:rerun-if-changed={}", png.display());

    let file = std::fs::File::open(&png).expect("the application icon is in the repository");
    let mut reader = png::Decoder::new(BufReader::new(file))
        .read_info()
        .expect("the application icon is a readable PNG");
    let size = reader
        .output_buffer_size()
        .expect("the icon is small enough to buffer");
    let mut pixels = vec![0u8; size];
    let frame = reader.next_frame(&mut pixels).expect("the icon decodes");
    assert!(
        frame.bit_depth == png::BitDepth::Eight,
        "the icon must be 8 bits per channel"
    );
    pixels.truncate(frame.buffer_size());
    pixels = match frame.color_type {
        png::ColorType::Rgba => pixels,
        png::ColorType::Rgb => {
            let (triples, _) = pixels.as_chunks::<3>();
            triples
                .iter()
                .flat_map(|&[r, g, b]| [r, g, b, 0xff])
                .collect()
        }
        other => panic!("the icon must be RGB or RGBA, not {other:?}"),
    };

    let out =
        std::path::Path::new(&std::env::var("OUT_DIR").expect("cargo sets OUT_DIR")).to_owned();
    std::fs::write(out.join("icon.rgba"), &pixels).expect("write the icon pixels");
    std::fs::write(
        out.join("icon-size.txt"),
        format!("{},{}", frame.width, frame.height),
    )
    .expect("write the icon dimensions");

    #[cfg(windows)]
    {
        let ico = assets.join("icon.ico");
        println!("cargo:rerun-if-changed={}", ico.display());
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon(ico.to_str().expect("the icon path is UTF-8"));
        resource.compile().expect("compile the Windows resource");
    }
}
