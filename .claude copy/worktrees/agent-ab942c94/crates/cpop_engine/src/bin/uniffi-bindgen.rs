

/
/
/
/
/
fn main() {
    #[cfg(feature = "ffi")]
    uniffi::uniffi_bindgen_main();

    #[cfg(not(feature = "ffi"))]
    {
        eprintln!("uniffi-bindgen requires the 'ffi' feature.");
        eprintln!("Run with: cargo run --features ffi --bin uniffi-bindgen -- <args>");
        std::process::exit(1);
    }
}
