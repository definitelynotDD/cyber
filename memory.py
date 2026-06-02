"""Agent memory.

Two layers:
  * Structured facts (subdomains, open ports, etc.) live in a plain dict —
    exact lookups, no embeddings needed. This is the right tool for
    "what ports are open".
  * Unstructured notes (page text, banners, observations) go into a FAISS
    vector index for semantic recall. This is where FAISS actually earns
    its place.

If sentence-transformers / faiss aren't installed, the semantic layer falls
back to a naive keyword match so the rest of the system keeps working.
"""
from __future__ import annotations

import threading
from typing import Any

import config

# --- optional heavy deps, degrade gracefully -------------------------------
try:
    import faiss  # type: ignore
    import numpy as np
    from sentence_transformers import SentenceTransformer  # type: ignore

    _EMBEDDINGS_AVAILABLE = True
except Exception:  # pragma: no cover - depends on environment
    _EMBEDDINGS_AVAILABLE = False


class MemoryStore:
    """Per-target memory. One instance per scan run."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._facts: dict[str, Any] = {}
        self._notes: list[str] = []
        self._lock = threading.Lock()

        self._model = None
        self._index = None
        self._dim = None
        if _EMBEDDINGS_AVAILABLE:
            try:
                self._model = SentenceTransformer(config.EMBED_MODEL)
                self._dim = self._model.get_sentence_embedding_dimension()
                self._index = faiss.IndexFlatIP(self._dim)
            except Exception:
                self._model = None  # fall back to keyword search

    # -- structured facts ---------------------------------------------------
    def set_fact(self, key: str, value: Any) -> None:
        with self._lock:
            self._facts[key] = value

    def get_fact(self, key: str, default: Any = None) -> Any:
        return self._facts.get(key, default)

    def all_facts(self) -> dict[str, Any]:
        return dict(self._facts)

    # -- semantic notes -----------------------------------------------------
    def add_note(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        with self._lock:
            self._notes.append(text)
            if self._model is not None and self._index is not None:
                vec = self._embed([text])
                self._index.add(vec)

    def query_notes(self, query: str, k: int = 3) -> list[str]:
        if not self._notes:
            return []
        if self._model is not None and self._index is not None:
            qv = self._embed([query])
            k = min(k, len(self._notes))
            _scores, idx = self._index.search(qv, k)
            return [self._notes[i] for i in idx[0] if 0 <= i < len(self._notes)]
        # keyword fallback
        terms = set(query.lower().split())
        ranked = sorted(
            self._notes,
            key=lambda n: len(terms & set(n.lower().split())),
            reverse=True,
        )
        return ranked[:k]

    def _embed(self, texts: list[str]):
        vecs = self._model.encode(texts, normalize_embeddings=True)
        return np.asarray(vecs, dtype="float32")

    # -- summary for the report / supervisor --------------------------------
    def summary(self) -> str:
        f = self._facts
        parts = [f"Target: {self.target}"]
        if "subdomains" in f:
            parts.append(f"Subdomains discovered: {len(f['subdomains'])}")
        if "open_ports" in f:
            total = sum(len(v) for v in f["open_ports"].values())
            parts.append(f"Open ports across hosts: {total}")
        if "vulnerabilities" in f:
            parts.append(f"Potential findings: {len(f['vulnerabilities'])}")
        if "vision_findings" in f:
            parts.append("Visual analysis: complete")
        return " | ".join(parts)
