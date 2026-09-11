use rpass::crypto::kdf::{Kdf, KdfParams, SecretVec};

fn main() {
    let pw = SecretVec::new(b"benchmark-password".to_vec().into_boxed_slice());
    let salt = [0u8; 16];
    for t in [36u32, 38u32] {
        let params = KdfParams::new(64, t, 1).unwrap();
        let kdf = Kdf::new(params);
        // warm-up discarded, measure the second run
        let _ = kdf.derive(&pw, &salt).unwrap();
        let start = std::time::Instant::now();
        let _ = kdf.derive(&pw, &salt).unwrap();
        let el = start.elapsed();
        println!("t={t:>2}: {:.3}s", el.as_secs_f64());
    }
}
// t=13 gives ~0.37s at 64 MiB on this machine — far from 1s. Try higher t
// and higher m to see the cost curve for the 1s target.
