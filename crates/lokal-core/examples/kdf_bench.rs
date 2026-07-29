use lokal_core::crypto::{KdfParams, derive_kek};
use std::time::Instant;

fn main() {
    let salt = [7u8; 16];
    for (label, p) in [
        ("32 MiB / t=2 / p=4", KdfParams { m_cost: 32 * 1024, t_cost: 2, p_cost: 4 }),
        ("64 MiB / t=3 / p=4 (当前默认)", KdfParams { m_cost: 64 * 1024, t_cost: 3, p_cost: 4 }),
        ("128 MiB / t=4 / p=4", KdfParams { m_cost: 128 * 1024, t_cost: 4, p_cost: 4 }),
    ] {
        let t0 = Instant::now();
        let n = 3;
        for _ in 0..n {
            std::hint::black_box(derive_kek(b"a-realistic-master-password", &salt, p).unwrap());
        }
        println!("{label:<32} {:>7.0} ms/次", t0.elapsed().as_secs_f64() * 1000.0 / n as f64);
    }
}
