//! Wire-format codec benchmarks: header encode/decode, framing decoder.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rnl_core::framing::FrameDecoder;
use rnl_core::packet::{frame, Header, HEADER_LEN};
use rnl_core::BufferPool;

fn bench_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("header");
    let h = Header::new(frame::DATA, 0xdead_beef_1234_5678, 12345);
    group.bench_function("encode", |b| {
        b.iter(|| {
            let mut buf = [0u8; HEADER_LEN];
            h.encode_into(&mut buf);
            black_box(buf)
        })
    });
    let bytes = h.encode();
    group.bench_function("decode", |b| {
        b.iter(|| black_box(Header::decode(black_box(&bytes)).unwrap()))
    });
    group.finish();
}

fn bench_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("framing");
    let frame_data = vec![0xABu8; 1356];
    let mut wire = Vec::new();
    for _ in 0..32 {
        rnl_core::framing::encode_framed(&frame_data, &mut wire).unwrap();
    }
    group.bench_function("decode_32_frames", |b| {
        b.iter(|| {
            let mut dec = FrameDecoder::new();
            let frames = dec.feed(black_box(&wire)).unwrap();
            black_box(frames.len())
        })
    });
    group.finish();
}

fn bench_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool");
    let pool = BufferPool::new(1500, 64);
    group.bench_function("get_drop", |b| {
        b.iter(|| {
            let mut buf = pool.get();
            buf[0] = 1;
            black_box(buf[0])
        })
    });
    group.bench_function("alloc_baseline", |b| {
        b.iter(|| {
            let mut buf = vec![0u8; 1500];
            buf[0] = 1;
            black_box(buf.len());
            buf
        })
    });
    group.finish();
}

criterion_group!(benches, bench_header, bench_framing, bench_pool);
criterion_main!(benches);
