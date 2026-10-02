# Input data

Raw and processed datasets are intentionally not included in this repository.
Place a pipeline-compatible CSV, JSON, JSONL, or Parquet file in this directory,
or pass its path explicitly to `context-audit`.

The minimum useful fields are:

- `sample_id`: unique sample identifier;
- `func_before`: vulnerable function;
- `func_after`: fixed function;
- `cwe`: known CWE label.

Optional metadata fields include `commit_id`, `project`, `commit_msg`,
`commit_msg_anonymized`, `bug_description`, and
`bug_description_anonymized`. When both original and anonymized text exist, the
pipeline prefers the anonymized field.

See `examples/sample.json` for a compact example. Dataset licenses and access
conditions remain the responsibility of the user.
