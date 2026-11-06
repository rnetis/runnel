//! Session crypto benchmarks: the actual data-path cost per packet.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rnl_core::packet::frame;
use rnl_core::session::Session;
use rnl_crypto::handshake;

fn pair() -> (Session, Session) {
    let (c, s) = handshake::in_memory_handshake().unwrap();
    (
        Session::from_handshake(1, c, true).unwrap(),
        Session::from_handshake(1, s, false).unwrap(),
    )
}

fn bench_seal_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("session");
    for &size in &[64usize, 576, 1200, 1340] {
        let payload = vec![0x42u8; size];
        let (mut client, mut server) = pair();

        group.bench_function(format!("seal_{size}b"), |b| {
            b.iter(|| black_box(client.seal(frame::DATA, black_box(&payload)).unwrap()))
        });

        group.bench_function(format!("open_{size}b"), |b| {
            b.iter(|| {
                // Seal fresh per iteration: replay protection correctly
                // rejects reuse, so each open consumes a unique packet.
                let w = client.seal(frame::DATA, &payload).unwrap();
                black_box(server.open(&w).unwrap())
            })
        });

        // Batched sealing.
        let payloads: Vec<&[u8]> = vec![&payload; 16];
        let mut out = Vec::new();
        group.bench_function(format!("seal_batch16_{size}b"), |b| {
            b.iter(|| {
                out.clear();
                black_box(client.seal_batch(frame::DATA, &payloads, &mut out).unwrap())
            })
        });
    }
    group.finish();
}

fn bench_replay_window(c: &mut Criterion) {
    use rnl_crypto::replay::SlidingWindow;
    let mut group = c.benchmark_group("replay");
    let mut w = SlidingWindow::new();
    let mut pn = 0u64;
    group.bench_function("check_and_update_in_order", |b| {
        b.iter(|| {
            pn += 1;
            black_box(w.check_and_update(pn))
        })
    });
    group.finish();
}

criterion_group!(benches, bench_seal_open, bench_replay_window);
criterion_main!(benches);
