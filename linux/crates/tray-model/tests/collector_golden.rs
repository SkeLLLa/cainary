use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use cainary_tray_model::collector::{Line, decode_line};

#[test]
fn decodes_the_net_jsonl_goldens() {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../crates/cainary-net/tests/golden");
    let files = [
        "claude-code-2.1.316.logs.jsonl",
        "claude-code-2.1.316.metrics.jsonl",
        "codex-0.166.0.logs.jsonl",
    ];
    let mut hellos = 0;
    let mut batches = 0;

    for name in files {
        let path = directory.join(name);
        let file = File::open(&path).unwrap_or_else(|error| {
            panic!("couldn't open {}: {error}", path.display());
        });
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.unwrap();
            match decode_line(&line).unwrap_or_else(|error| {
                panic!("{}:{} didn't decode: {error:?}", path.display(), index + 1);
            }) {
                Line::Hello(hello) => {
                    assert!(!hello.endpoint.is_empty());
                    assert!(!hello.setup.claude_code.is_empty());
                    hellos += 1;
                }
                Line::Batch(batch) => {
                    assert!(batch.seq > 0);
                    assert!(!batch.path.is_empty());
                    assert!(!batch.summary.records.is_empty());
                    batches += 1;
                }
                other => panic!("unexpected JSONL line in {}: {other:?}", path.display()),
            }
        }
    }

    assert_eq!(hellos, files.len());
    assert_eq!(batches, files.len());
}
