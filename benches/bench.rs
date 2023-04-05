use std::{fmt, ops::Deref};

use criterion::{
    black_box, criterion_group, criterion_main, AxisScale, BenchmarkId, Criterion,
    PlotConfiguration, Throughput,
};
use rand::{distributions::Standard, thread_rng, Rng};

const INPUT_SIZES: &[usize] = &[16, 23, 32, 47, 128, 256, 512, 1024, 1024 * 1024];

fn bench_everything(c: &mut Criterion) {
    let all_data: Vec<_> = INPUT_SIZES
        .iter()
        .copied()
        .map(Data::new)
        .collect::<Vec<_>>();

    let mut group = c.benchmark_group("naive-sha256 vs sha2-sha256-soft");

    for data in all_data {
        let param = format!("{:?}", data);
        group.bench_with_input(
            BenchmarkId::new("bench naive-sha256", &param),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = naive_sha256::Sha256::new();
                    hasher.update(data.deref());
                    black_box(hasher.finalize());
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("bench sha2-sha256-soft", &param),
            &data,
            |b, data| {
                use sha2::Digest;
                b.iter(|| {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(data.deref());
                    black_box(hasher.finalize());
                })
            },
        );
        group.throughput(Throughput::Bytes(data.0.len() as u64));
        group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    }

    group.finish();
}

struct Data(Vec<u8>);

impl Data {
    fn new(len: usize) -> Self {
        let data = thread_rng().sample_iter(&Standard).take(len).collect();
        Self(data)
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::ops::Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.len())
    }
}

criterion_group!(benches, bench_everything);
criterion_main!(benches);
