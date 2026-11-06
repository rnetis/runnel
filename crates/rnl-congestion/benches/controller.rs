//! Congestion controller and scheduler benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rnl_congestion::{NewReno, Priority, Scheduler};

fn bench_controller(c: &mut Criterion) {
    let mut group = c.benchmark_group("congestion");
    group.bench_function("ack_cycle_1000", |b| {
        b.iter(|| {
            let mut c = NewReno::new(10, 1380);
            let now = std::time::Instant::now();
            for _ in 0..1000 {
                c.on_packet_sent(1340);
                c.on_ack(1340, Some(std::time::Duration::from_millis(20)), now);
            }
            black_box(c.cwnd())
        })
    });
    group.bench_function("pacing_rate", |b| {
        let mut c = NewReno::new(10, 1380);
        let now = std::time::Instant::now();
        for _ in 0..100 {
            c.on_ack(1340, Some(std::time::Duration::from_millis(20)), now);
        }
        b.iter(|| black_box(c.pacing_rate()))
    });
    group.finish();
}

fn bench_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler");
    group.bench_function("push_pop_mixed_1000", |b| {
        b.iter(|| {
            let mut s = Scheduler::new();
            for i in 0..1000u32 {
                let prio = match i % 4 {
                    0 => Priority::Critical,
                    1 => Priority::Interactive,
                    2 => Priority::Normal,
                    _ => Priority::Bulk,
                };
                s.push(prio, i);
            }
            let mut n = 0;
            while s.pop().is_some() {
                n += 1;
            }
            black_box(n)
        })
    });
    group.finish();
}

criterion_group!(benches, bench_controller, bench_scheduler);
criterion_main!(benches);
