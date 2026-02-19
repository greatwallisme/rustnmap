//! NSE (Nmap Scripting Engine) performance benchmarks for `RustNmap`.
//!
//! This module benchmarks Lua script execution overhead, library function
//! call overhead, and script scheduling performance.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rustnmap_nse::engine::SchedulerConfig;
use rustnmap_nse::{
    ScriptCategory, ScriptDatabase, ScriptEngine, ScriptScheduler, DEFAULT_SCRIPT_TIMEOUT,
    MAX_CONCURRENT_SCRIPTS, MAX_MEMORY_BYTES, NSE_VERSION,
};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

/// Benchmark script database operations.
fn bench_script_database(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_script_database");

    group.bench_function("create_empty_database", |b| {
        b.iter(|| {
            let db = ScriptDatabase::new();
            black_box(db);
        });
    });

    group.bench_function("register_single_script", |b| {
        b.iter(|| {
            let mut db = ScriptDatabase::new();
            // Create a new script with unique ID for each iteration
            let unique_script = create_test_script(
                &format!(
                    "test-script-{}",
                    std::time::Instant::now().elapsed().as_nanos()
                ),
                ScriptCategory::Default,
            );
            db.register_script(&unique_script);
        });
    });

    group.bench_function("lookup_script_by_id", |b| {
        let mut db = ScriptDatabase::new();
        let script = create_test_script("lookup-test", ScriptCategory::Default);
        db.register_script(&script);

        b.iter(|| {
            let result = db.get("lookup-test");
            black_box(result);
        });
    });

    group.bench_function("select_by_category", |b| {
        let db = create_populated_database(100);

        b.iter(|| {
            let scripts = db.select_by_category(&[ScriptCategory::Vuln]);
            black_box(scripts);
        });
    });

    group.bench_function("select_by_pattern", |b| {
        let db = create_populated_database(100);

        b.iter(|| {
            let scripts = db.select_by_pattern("http");
            black_box(scripts);
        });
    });

    group.finish();
}

/// Benchmark script scheduler operations.
fn bench_script_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_script_scheduler");

    group.bench_function("create_scheduler", |b| {
        let db = Arc::new(ScriptDatabase::new());
        let config = SchedulerConfig::default();

        b.iter(|| {
            let scheduler = ScriptScheduler::new(Arc::clone(&db), config.clone());
            black_box(scheduler);
        });
    });

    group.bench_function("scheduler_select_scripts", |b| {
        let db = Arc::new(create_populated_database(100));
        let config = SchedulerConfig::default();
        let scheduler = ScriptScheduler::new(db, config);

        b.iter(|| {
            let scripts =
                scheduler.select_scripts(&[ScriptCategory::Default, ScriptCategory::Safe]);
            black_box(scripts);
        });
    });

    group.finish();
}

/// Benchmark script engine operations.
fn bench_script_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_script_engine");

    group.bench_function("create_engine", |b| {
        b.iter(|| {
            let db = ScriptDatabase::new();
            let engine = ScriptEngine::new(db);
            black_box(engine);
        });
    });

    group.bench_function("create_engine_with_config", |b| {
        b.iter(|| {
            let db = ScriptDatabase::new();
            let config = SchedulerConfig {
                max_concurrent: 10,
                default_timeout: Duration::from_secs(60),
                max_memory: 5 * 1024 * 1024,
            };
            let engine = ScriptEngine::with_config(db, config);
            black_box(engine);
        });
    });

    group.finish();
}

/// Benchmark Lua script execution.
fn bench_lua_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_lua_execution");

    group.bench_function("execute_simple_script", |b| {
        let mut db = ScriptDatabase::new();
        let script = create_script_with_source(
            "simple-script",
            r#"
action = function(host)
    return "test output"
end
"#,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let target_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        b.iter(|| {
            let result =
                engine.execute_script(engine.database().get("simple-script").unwrap(), target_ip);
            let _ = black_box(result);
        });
    });

    group.bench_function("execute_script_with_math", |b| {
        let mut db = ScriptDatabase::new();
        let script = create_script_with_source(
            "math-script",
            r"
action = function(host)
    local sum = 0
    for i = 1, 100 do
        sum = sum + i
    end
    return sum
end
",
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let target_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        b.iter(|| {
            let result =
                engine.execute_script(engine.database().get("math-script").unwrap(), target_ip);
            let _ = black_box(result);
        });
    });

    group.bench_function("execute_script_with_string_ops", |b| {
        let mut db = ScriptDatabase::new();
        let script = create_script_with_source(
            "string-script",
            r#"
action = function(host)
    local result = ""
    for i = 1, 100 do
        result = result .. "x"
    end
    return #result
end
"#,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let target_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        b.iter(|| {
            let result =
                engine.execute_script(engine.database().get("string-script").unwrap(), target_ip);
            let _ = black_box(result);
        });
    });

    group.finish();
}

/// Benchmark NSE constants and configuration.
fn bench_nse_constants(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_constants");

    group.bench_function("read_version", |b| {
        b.iter(|| {
            let version = NSE_VERSION;
            black_box(version);
        });
    });

    group.bench_function("read_timeout", |b| {
        b.iter(|| {
            let timeout = DEFAULT_SCRIPT_TIMEOUT;
            black_box(timeout);
        });
    });

    group.bench_function("read_memory_limit", |b| {
        b.iter(|| {
            let limit = MAX_MEMORY_BYTES;
            black_box(limit);
        });
    });

    group.bench_function("read_concurrent_limit", |b| {
        b.iter(|| {
            let limit = MAX_CONCURRENT_SCRIPTS;
            black_box(limit);
        });
    });

    group.finish();
}

/// Benchmark scheduler configuration operations.
fn bench_scheduler_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_scheduler_config");

    group.bench_function("default_config", |b| {
        b.iter(|| {
            let config = SchedulerConfig::default();
            black_box(config);
        });
    });

    group.bench_function("custom_config", |b| {
        b.iter(|| {
            let config = SchedulerConfig {
                max_concurrent: 50,
                default_timeout: Duration::from_secs(120),
                max_memory: 20 * 1024 * 1024,
            };
            black_box(config);
        });
    });

    group.finish();
}

/// Benchmark script category operations.
fn bench_script_categories(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_script_categories");

    group.bench_function("create_all_categories", |b| {
        b.iter(|| {
            let categories = [
                ScriptCategory::Auth,
                ScriptCategory::Broadcast,
                ScriptCategory::Brute,
                ScriptCategory::Default,
                ScriptCategory::Discovery,
                ScriptCategory::Dos,
                ScriptCategory::Exploit,
                ScriptCategory::External,
                ScriptCategory::Fuzzer,
                ScriptCategory::Intrusive,
                ScriptCategory::Malware,
                ScriptCategory::Safe,
                ScriptCategory::Version,
                ScriptCategory::Vuln,
            ];
            black_box(categories);
        });
    });

    group.finish();
}

/// Benchmark script batch operations.
fn bench_script_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("nse_batch_operations");

    group.throughput(Throughput::Elements(100));
    group.bench_function("register_100_scripts", |b| {
        b.iter(|| {
            let mut db = ScriptDatabase::new();
            for i in 0..100 {
                let script =
                    create_test_script(&format!("batch-script-{i}"), ScriptCategory::Default);
                db.register_script(&script);
            }
            black_box(db);
        });
    });

    group.throughput(Throughput::Elements(100));
    group.bench_function("lookup_100_scripts", |b| {
        let mut db = ScriptDatabase::new();
        for i in 0..100 {
            let script =
                create_test_script(&format!("lookup-script-{i}"), ScriptCategory::Default);
            db.register_script(&script);
        }

        b.iter(|| {
            for i in 0..100 {
                let _ = db.get(&format!("lookup-script-{i}"));
            }
        });
    });

    group.finish();
}

/// Helper function to create a test script.
fn create_test_script(id: &str, _category: ScriptCategory) -> rustnmap_nse::NseScript {
    rustnmap_nse::NseScript::new(
        id,
        std::path::PathBuf::from(format!("/test/{id}.nse")),
        String::new(),
    )
}

/// Helper function to create a script with source code.
fn create_script_with_source(id: &str, source: &str) -> rustnmap_nse::NseScript {
    rustnmap_nse::NseScript::new(
        id,
        std::path::PathBuf::from(format!("/test/{id}.nse")),
        source.to_string(),
    )
}

/// Helper function to create a populated database with test scripts.
fn create_populated_database(count: usize) -> ScriptDatabase {
    let mut db = ScriptDatabase::new();

    let categories = [
        ScriptCategory::Default,
        ScriptCategory::Safe,
        ScriptCategory::Vuln,
        ScriptCategory::Discovery,
        ScriptCategory::Version,
    ];

    for i in 0..count {
        let category = categories[i % categories.len()];
        let script = create_test_script(&format!("test-script-{i}"), category);
        db.register_script(&script);
    }

    db
}

criterion_group!(
    nse_benches,
    bench_script_database,
    bench_script_scheduler,
    bench_script_engine,
    bench_lua_execution,
    bench_nse_constants,
    bench_scheduler_config,
    bench_script_categories,
    bench_script_batch_operations
);

criterion_main!(nse_benches);
