This `rag-sanitizer` tool is used to solve one core problem: stop malicious or hidden instructions from entering RAG context through documents.

Typical real-world usage patterns:

1. Security-first ingestion
- Goal: block risky documents from ever being indexed.
- How: run sanitizer right after loading docs, set policy to `drop` for high threat docs.

2. Keep docs but clean them
- Goal: preserve useful content while removing attack payloads.
- How: use `sanitize`, index `result.sanitized_text`.

3. Compliance/audit workflow
- Goal: prove what was detected and why.
- How: store `threat_score`, `rule_id`, and `signals` metadata alongside chunks.

4. Internal knowledge bases with mixed trust
- Goal: avoid aggressive blocking on mostly safe docs.
- How: use `flag` mode, keep docs, route high-score docs for review.

5. Framework-native integration
- LangChain teams: plug in `RagSanitizerTransformer` before chunking/splitting.
- LlamaIndex teams: use `RagSanitizerPostprocessor` in ingestion or retrieval.

The “what they want to do” outcome is usually one of these:
- prevent prompt injection in answers,
- reduce poisoned retrieval behavior,
- avoid hidden exfiltration links/tags,
- add security telemetry to RAG pipelines.

I created a production policy matrix that shows what thresholds + `sanitize/drop/flag` per data source: web, PDFs, Confluence, Notion, internal docs.

**Production Policy Matrix**

| Source type | Trust level | `on_threat` | `threat_threshold` | Recommended action |
|---|---|---|---|---|
| Public web pages | Low | `drop` | `0.25` | Skip document if unsafe; log source URL + signals |
| User-uploaded PDFs | Low | `sanitize` | `0.30` | Keep cleaned text, store removed count and rule IDs |
| Confluence/Notion exports | Medium | `sanitize` | `0.35` | Clean + keep, alert if score > 0.6 |
| Internal docs (controlled) | High | `flag` | `0.45` | Keep text, add threat metadata for review |
| Third-party vendor docs | Low-Med | `sanitize` | `0.30` | Clean + quarantine if critical signals found |
| Retrieved chunks (post-retrieval check) | Mixed | `drop` | `0.30` | Drop risky chunks before final prompt assembly |

**Baseline defaults to start**
1. Keep all analyzers enabled.
2. Use `sanitize` for most ingestion sources.
3. Automatically `drop` only on critical-only patterns or score > `0.8`.
4. Persist `threat_score`, `signal_count`, `signals`, `removed_count` in your vector metadata.


**How To Deploy**

**A) Deploy as a library inside your ingestion workers (most common)**
1. Install:
```bash
pip install rag-sanitizer
```
2. Put sanitizer step immediately after document loading and before chunking/embedding.
3. Roll out by source type:
- week 1: `flag` mode only (observe)
- week 2: `sanitize`
- week 3: `drop` for highest-risk sources
4. Add dashboards on:
- docs scanned/day
- docs flagged/day
- top `rule_id`
- average threat score by source

**B) Deploy as a shared internal service (if many teams ingest docs)**
1. Wrap `RagSanitizer` in a small API (FastAPI/Flask).
2. Endpoint: `POST /scan` with `{text, metadata}`.
3. Return `ScanResult`.
4. All ingestion pipelines call this service before indexing.

**Release checklist**
1. `pip install -e ".[dev,all]"`
2. `pytest --cov=rag_sanitizer -v`
3. `ruff check rag_sanitizer tests`
4. `ruff format --check rag_sanitizer tests`
5. Tag release (`v0.1.0`) and publish to PyPI.
6. Roll out with `flag -> sanitize -> selective drop`.