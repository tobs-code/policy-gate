use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use firewall_core::evaluate_raw;

/// Worst-case inputs for the normalisation pipeline (NFKC→NFD→strip Mn→NFC).
fn zalgo_payload(len: usize) -> String {
    // Combining grave accent (U+0300) after every ASCII char — maximum Mn density.
    let unit = "a\u{0300}";
    unit.chars()
        .cycle()
        .take(len * unit.chars().count())
        .collect::<String>()
        .chars()
        .take(len)
        .collect()
}

fn ascii_payload(len: usize) -> String {
    "What is the capital of France? "
        .chars()
        .cycle()
        .take(len)
        .collect()
}

pub fn bench_normalise(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("normalise_pipeline");

    for size in [256usize, 1024, 4096, 8192] {
        group.throughput(Throughput::Bytes(size as u64));

        // Typical input — ASCII, no combining marks.
        group.bench_with_input(BenchmarkId::new("ascii", size), &size, |b, &s| {
            let input = ascii_payload(s);
            b.iter(|| evaluate_raw(&input, 0));
        });

        // Worst-case — maximum combining-mark density (Zalgo-style).
        group.bench_with_input(BenchmarkId::new("zalgo", size), &size, |b, &s| {
            let input = zalgo_payload(s);
            b.iter(|| evaluate_raw(&input, 0));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_normalise);
criterion_main!(benches);
