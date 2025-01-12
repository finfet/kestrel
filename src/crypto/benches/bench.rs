use kestrel_crypto::chapoly_encrypt_ietf;

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_chacha20poly1305(c: &mut Criterion) {
    let pt = vec![0u8; 65536];
    let key = hex::decode("d288ba9a54bd715bab15edf8aa329cce0b416add4ae3fe672cd151b632ad4ed3").unwrap();
    let nonce = [0u8; 12];
    c.bench_function("chapoly encrypt", |b| b.iter(|| {
        chapoly_encrypt_ietf(key.as_slice(), &nonce, pt.as_slice(), &[]);
    }));
}

criterion_group!(benches, bench_chacha20poly1305);
criterion_main!(benches);
