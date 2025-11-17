// crates/ledger/tests/support/mod.rs
pub mod tx_build;

#[cfg(feature = "persistence")]
mod tmpdb {
    use eezo_ledger::persistence::Persistence;
    use tempfile::TempDir;
    #[allow(dead_code)] 
    pub fn temp_persistence() -> (Persistence, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        // Adjust the open call if your API differs (Path vs &str etc.)
        let p = Persistence::open_default(dir.path()).expect("open persistence");
        (p, dir)
    }
}
#[allow(unused_imports)] // This will silence the clippy warning
#[cfg(feature = "persistence")]
pub use tmpdb::temp_persistence;
