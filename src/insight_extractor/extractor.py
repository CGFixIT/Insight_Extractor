"""Main InsightExtractor class tying together NLP/ML extraction pipelines."""

from __future__ import annotations

import json
import logging
import re
import warnings
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]
from sklearn.metrics.pairwise import cosine_similarity  # type: ignore[import-untyped]

from insight_extractor.config import KeywordCategory, StemMode
from insight_extractor.constants import REGEX_PATTERNS, THREAD_SEEDS
from insight_extractor.exceptions import ConfigLoadError, ModelLoadError, StateLoadError
from insight_extractor.models import (
    ExtractResult,
    KeywordStats,
    SemanticHit,
    SentenceScore,
)
from insight_extractor.stemmer import DynamicKeywordStemmer, KeywordPatternRegistry
from insight_extractor.tokenizer import SentenceTokenizer
from insight_extractor.utils import compute_text_hash, format_timestamp

logger = logging.getLogger("insight_extractor")

# ---------------------------------------------------------------------------
# Heuristic keyword buckets for auto-categorisation
# ---------------------------------------------------------------------------
threat_terms: set[str] = {
    "ransomware",
    "malware",
    "trojan",
    "worm",
    "backdoor",
    "rootkit",
    "spyware",
    "adware",
    "keylogger",
    "botnet",
    "ddos",
    "phishing",
    "spearphishing",
    "whaling",
    "vishing",
    "smishing",
    "exploit",
    "0day",
    "zero-day",
    "cve",
    "payload",
    "stager",
    "dropper",
    "crypter",
    "packer",
    "binder",
    "downloader",
    "rat",
    "c2",
    "command and control",
    "apt",
    "advanced persistent threat",
    "lateral movement",
    "privilege escalation",
    "persistence",
    "defense evasion",
    "credential dumping",
    "brute force",
    "password spraying",
    "pass-the-hash",
    "pass-the-ticket",
    "golden ticket",
    "kerberoasting",
    "living off the land",
    "fileless malware",
    "supply chain attack",
    "watering hole",
    "drive-by download",
    "man-in-the-middle",
    "session hijacking",
    "sql injection",
    "xss",
    "cross-site scripting",
    "csrf",
    "remote code execution",
    "rce",
    "arbitrary code execution",
    "buffer overflow",
    "stack overflow",
    "heap overflow",
    "use-after-free",
    "race condition",
    "format string",
    "integer overflow",
    "type confusion",
    "deserialization",
    "xml external entity",
    "xxe",
    "server-side request forgery",
    "ssrf",
    "insecure direct object reference",
    "idor",
    "security misconfiguration",
    "sensitive data exposure",
    "insufficient logging",
    "denial of service",
    "dos",
    "distributed denial of service",
    "cryptojacking",
    "ransomware-as-a-service",
    "raas",
    "malware-as-a-service",
    "phishing-as-a-service",
    "c2-as-a-service",
    "blackmatter",
    "darkside",
    "revil",
    "sodinokibi",
    "conti",
    "lockbit",
    "blackcat",
    "alphv",
    "clop",
    "maze",
    "egregor",
    "sekhmet",
    "netwalker",
    "avaddon",
    "babuk",
    "hive",
    "hello kitty",
    "quantum",
    "royal",
    "black busta",
    "play",
    "medusa",
    "akira",
    "inc ransom",
    "nitrogen",
}

osint_terms: set[str] = {
    "osint",
    "open source intelligence",
    "socmint",
    "geoint",
    "humint",
    "sigint",
    "imint",
    "masint",
    "fisint",
    "reconnaissance",
    "recon",
    "footprinting",
    "scanning",
    "enumeration",
    "information gathering",
    "data mining",
    "web scraping",
    "social engineering",
    "pretexting",
    "impersonation",
    "doxing",
    "dox",
    "swatting",
    "breach",
    "data breach",
    "leak",
    "dump",
    "database dump",
    "pastebin",
    "github recon",
    "subdomain enumeration",
    "dns enumeration",
    "reverse dns",
    "whois lookup",
    "shodan",
    "censys",
    "binaryedge",
    "onyphe",
    "fofa",
    "theharvester",
    "maltego",
    "spiderfoot",
    "recon-ng",
    "sherlock",
    "holehe",
    "ghunt",
    "tweepy",
    "wayback machine",
    "archive.org",
    "google dork",
    "google dorking",
    "site:",
    "inurl:",
    "intitle:",
    "filetype:",
    "cache:",
    "linkedin scraping",
    "email harvesting",
    "phone lookup",
    "skip tracing",
    "license plate lookup",
    "vin lookup",
    "ssn",
    "social security number",
    "pii",
    "personally identifiable",
    "public records",
    "court records",
    "property records",
}

safety_terms: set[str] = {
    "safety",
    "alignment",
    "jailbreak",
    "prompt injection",
    "adversarial prompt",
    "model extraction",
    "membership inference",
    "data poisoning",
    "model poisoning",
    "backdoor attack",
    "evasion attack",
    "gradient attack",
    "privacy",
    "fairness",
    "bias",
    "transparency",
    "explainability",
    "robustness",
    "hallucination",
    "toxicity",
    "red teaming",
    "blue teaming",
    "purple teaming",
    "penetration testing",
    "vulnerability assessment",
    "risk assessment",
    "incident response",
    "forensics",
    "threat hunting",
    "threat intelligence",
    "threat feed",
    "ioc",
    "indicator of compromise",
    "ttp",
    "tactics techniques procedures",
    "mitre att&ck",
    "kill chain",
    "cyber kill chain",
    "diamond model",
    "pyramid of pain",
    "alert fatigue",
    "false positive",
    "false negative",
    "mean time to detect",
    "mean time to respond",
    "sla",
    "runbook",
    "playbook",
    "soar",
    "siem",
    "edr",
    "xdr",
    "ndr",
    "mdr",
    "endpoint detection",
    "network detection",
    "deception",
    "honeypot",
    "honeytoken",
    "canary token",
}

ai_terms: set[str] = {
    "ai",
    "artificial intelligence",
    "machine learning",
    "ml",
    "deep learning",
    "neural network",
    "transformer",
    "attention mechanism",
    "bert",
    "gpt",
    "llm",
    "large language model",
    "foundation model",
    "generative ai",
    "genai",
    "diffusion model",
    "gan",
    "generative adversarial",
    "reinforcement learning",
    "rl",
    "rlhf",
    "reinforcement learning from human feedback",
    "fine-tuning",
    "peft",
    "lora",
    "qlora",
    "prompt engineering",
    "chain of thought",
    "cot",
    "tree of thoughts",
    "rag",
    "retrieval augmented generation",
    "vector database",
    "embedding",
    "semantic search",
    "clustering",
    "classification",
    "named entity recognition",
    "ner",
    "sentiment analysis",
    "topic modelling",
    "dimensionality reduction",
    "pca",
    "tsne",
    "umap",
    "tensorflow",
    "pytorch",
    "jax",
    "onnx",
    "huggingface",
    "langchain",
    "llamaindex",
    "chromadb",
    "pinecone",
    "weaviate",
    "milvus",
    "qdrant",
    "faiss",
    "annoy",
    "openai",
    "anthropic",
    "google gemini",
    "claude",
    "llama",
    "mistral",
    "mixtral",
    "falcon",
    "phi",
}


type CategoryMap = dict[str, KeywordCategory]


class InsightExtractor:
    """Main extraction engine: regex, dynamic keyword, semantic, and sentence scoring."""

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        config_path: str | Path | None = None,
        seed_keywords: list[str] | None = None,
        top_k: int = 10,
        similarity_threshold: float = 0.38,
        dynamic_expansion_top_n: int = 15,
        *,
        stem_mode: StemMode = StemMode.STEM,
        enable_dynamic_regex: bool = True,
        custom_stem_suffixes: tuple[str, ...] | None = None,
        output_dir: str | Path = ".",
    ) -> None:
        self.model_name = model_name
        self.config_path = Path(config_path) if config_path else None
        self.top_k = top_k
        self.similarity_threshold = similarity_threshold
        self.dynamic_expansion_top_n = dynamic_expansion_top_n
        self.stem_mode = stem_mode
        self.enable_dynamic_regex = enable_dynamic_regex
        self.custom_stem_suffixes = custom_stem_suffixes
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # ---- keyword bank --------------------------------------------------
        self.thread_keywords: list[str] = list(seed_keywords) if seed_keywords else []
        if not self.thread_keywords and hasattr(THREAD_SEEDS, "__iter__"):
            self.thread_keywords = list(THREAD_SEEDS)

        self.keyword_freq: Counter[str] = Counter(self.thread_keywords)
        self.keyword_categories: CategoryMap = {}

        # ---- config file ---------------------------------------------------
        if self.config_path and self.config_path.exists():
            try:
                cfg = self._load_config(self.config_path)
                if isinstance(cfg, dict):
                    if "seed_keywords" in cfg:
                        self.thread_keywords = list(cfg["seed_keywords"])
                    if "similarity_threshold" in cfg:
                        self.similarity_threshold = float(cfg["similarity_threshold"])
                    if "stem_mode" in cfg:
                        self.stem_mode = StemMode(cfg["stem_mode"])
            except ConfigLoadError:
                logger.warning("Failed to load config; using defaults.")

        # ---- stemmer + pattern registry ------------------------------------
        if self.custom_stem_suffixes is not None:
            self.stemmer = DynamicKeywordStemmer(
                stem_mode=self.stem_mode,
                case_sensitive=False,
                custom_suffixes=self.custom_stem_suffixes,
            )
        else:
            self.stemmer = DynamicKeywordStemmer(
                stem_mode=self.stem_mode,
                case_sensitive=False,
            )
        if self.thread_keywords:
            self.stemmer.set_keywords(self.thread_keywords)

        self.pattern_registry = KeywordPatternRegistry(
            static_patterns=REGEX_PATTERNS,
            stemmer=self.stemmer,
        )
        if self.thread_keywords:
            self.pattern_registry.regenerate_dynamic_patterns(self.thread_keywords)

        # ---- tokenizer + model placeholders --------------------------------
        self._tokenizer: SentenceTokenizer | None = None
        self._model: SentenceTransformer | None = None

        # ---- embeddings -----------------------------------------------------
        self._keyword_embeddings: np.ndarray | None = None

        # ---- TF-IDF corpus for dynamic expansion ---------------------------
        self._tfidf_corpus: list[str] = []
        self._auto_categorize_keywords()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------
    @staticmethod
    def _load_config(path: str | Path) -> dict[str, Any]:
        """Load configuration from TOML or YAML based on file extension."""
        p = Path(path)
        match p.suffix.lower():
            case ".toml":
                try:
                    import tomllib

                    with p.open("rb") as fh:
                        return tomllib.load(fh)
                except ImportError:
                    raise ConfigLoadError(
                        f"tomllib not available (Python 3.11+ required) for {p}"
                    ) from None
                except Exception as exc:
                    raise ConfigLoadError(f"Failed to load TOML config {p}: {exc}") from exc
            case ".yaml" | ".yml":
                try:
                    import yaml  # type: ignore[import-untyped]

                    with p.open(encoding="utf-8") as fh:
                        data = yaml.safe_load(fh)
                        if isinstance(data, dict):
                            return data
                        raise ConfigLoadError(f"YAML config {p} did not parse to a dict")
                except ImportError:
                    raise ConfigLoadError(
                        f"PyYAML not installed; cannot load YAML config {p}"
                    ) from None
                except Exception as exc:
                    raise ConfigLoadError(f"Failed to load YAML config {p}: {exc}") from exc
            case ".json":
                try:
                    with p.open(encoding="utf-8") as fh:
                        data = json.load(fh)
                        if isinstance(data, dict):
                            return data
                        raise ConfigLoadError(f"JSON config {p} did not parse to a dict")
                except Exception as exc:
                    raise ConfigLoadError(f"Failed to load JSON config {p}: {exc}") from exc
            case _:
                raise ConfigLoadError(
                    f"Unsupported config format '{p.suffix}' for {p}; "
                    "expected .toml, .yaml, .yml, or .json"
                )

    # ------------------------------------------------------------------
    # Lazy model loading
    # ------------------------------------------------------------------
    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load the sentence-transformers model."""
        if self._model is None:
            try:
                self._model = SentenceTransformer(self.model_name)
            except Exception as exc:
                raise ModelLoadError(
                    f"Failed to load SentenceTransformer model '{self.model_name}': {exc}"
                ) from exc
        return self._model

    @property
    def tokenizer(self) -> SentenceTokenizer:
        """Lazy-load the SentenceTokenizer."""
        if self._tokenizer is None:
            self._tokenizer = SentenceTokenizer(self.model_name)
        return self._tokenizer

    # ------------------------------------------------------------------
    # Keyword embeddings
    # ------------------------------------------------------------------
    def _recompute_keyword_embeddings(self) -> None:
        """Encode all thread keywords with the model and L2-normalise."""
        if not self.thread_keywords:
            self._keyword_embeddings = None
            return
        embeddings = self.model.encode(
            self.thread_keywords,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        # L2 normalisation
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        self._keyword_embeddings = embeddings / norms

    # ------------------------------------------------------------------
    # Auto-categorisation
    # ------------------------------------------------------------------
    def _auto_categorize_keywords(self) -> None:
        """Heuristic categorisation of keywords into KeywordCategory buckets."""
        _buckets: list[tuple[set[str], KeywordCategory]] = [
            (threat_terms, KeywordCategory.THREAT_INTEL),
            (osint_terms, KeywordCategory.OSINT),
            (safety_terms, KeywordCategory.CHILD_SAFETY),
            (ai_terms, KeywordCategory.AI_INFRA),
        ]
        for kw in self.thread_keywords:
            if kw in self.keyword_categories:
                continue  # already classified; skip re-computation
            kw_lower = kw.lower()
            assigned = KeywordCategory.GENERAL
            for terms, category in _buckets:
                if kw_lower in terms:
                    assigned = category
                    break
                if any(kw_lower in t or t in kw_lower for t in terms):
                    assigned = category
                    break
            self.keyword_categories[kw] = assigned

    # ------------------------------------------------------------------
    # Dynamic keyword expansion via TF-IDF + BERT similarity
    # ------------------------------------------------------------------
    def update_thread_keywords(
        self,
        new_text: str,
        *,
        auto_expand: bool = True,
    ) -> list[str]:
        """
        Append *new_text* to the TF-IDF corpus, extract candidate keywords,
        and add those that are semantically close to existing keywords.
        """
        self._tfidf_corpus.append(new_text)

        if not auto_expand or len(self._tfidf_corpus) == 0:
            return []

        # TF-IDF candidate extraction
        vectorizer = TfidfVectorizer(
            max_features=200,
            stop_words="english",
            ngram_range=(1, 3),
            min_df=1,
        )
        try:
            tfidf_matrix = vectorizer.fit_transform(self._tfidf_corpus)
        except ValueError:
            return []

        feature_names: list[str] = vectorizer.get_feature_names_out()
        if tfidf_matrix.shape[0] == 0 or len(feature_names) == 0:
            return []

        # Scores from the latest (most recent) document
        latest_row = tfidf_matrix[-1]
        scores = latest_row.toarray().flatten()
        top_indices = np.argsort(scores)[::-1][: self.dynamic_expansion_top_n]
        candidates = [feature_names[i] for i in top_indices if scores[i] > 0]

        if not candidates:
            return []

        # Ensure embeddings are fresh
        if self._keyword_embeddings is None and self.thread_keywords:
            self._recompute_keyword_embeddings()

        # If we have no existing keywords, add top candidates verbatim
        if not self.thread_keywords:
            newly_added: list[str] = []
            for cand in candidates:
                if cand not in self.thread_keywords:
                    self.thread_keywords.append(cand)
                    self.keyword_freq[cand] += 1
                    newly_added.append(cand)
            if newly_added:
                self.stemmer.set_keywords(self.thread_keywords)
                self.pattern_registry.regenerate_dynamic_patterns(self.thread_keywords)
                self._auto_categorize_keywords()
            return newly_added

        # Embed candidates and compare against existing keyword embeddings
        cand_embeddings = self.model.encode(
            candidates,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        cand_norms = np.linalg.norm(cand_embeddings, axis=1, keepdims=True)
        cand_norms[cand_norms == 0] = 1.0
        cand_embeddings = cand_embeddings / cand_norms

        # Max similarity for each candidate against all existing keywords
        similarities = cosine_similarity(cand_embeddings, self._keyword_embeddings)
        max_sims = similarities.max(axis=1)

        newly_added = []
        for cand, sim in zip(candidates, max_sims, strict=False):
            if sim >= self.similarity_threshold and cand not in self.thread_keywords:
                self.thread_keywords.append(cand)
                self.keyword_freq[cand] += 1
                newly_added.append(cand)

        if newly_added:
            self.stemmer.set_keywords(self.thread_keywords)
            self.pattern_registry.regenerate_dynamic_patterns(self.thread_keywords)
            self._recompute_keyword_embeddings()
            self._auto_categorize_keywords()

        return newly_added

    # ------------------------------------------------------------------
    # Regex entity extraction
    # ------------------------------------------------------------------
    def extract_regex_entities(self, text: str) -> dict[str, list[str]]:
        """Run static REGEX_PATTERNS against *text* and deduplicate matches."""
        results: dict[str, list[str]] = {}
        for label, pattern in REGEX_PATTERNS.items():
            matches = re.findall(pattern, text)
            # Deduplicate while preserving order
            seen: set[str] = set()
            unique: list[str] = []
            for m in matches:
                m_str = (
                    m.strip()
                    if isinstance(m, str)
                    else m[0].strip()
                    if isinstance(m, tuple) and m
                    else str(m)
                )
                if m_str and m_str not in seen:
                    seen.add(m_str)
                    unique.append(m_str)
            if unique:
                results[label] = unique
        return results

    # ------------------------------------------------------------------
    # Dynamic entity extraction
    # ------------------------------------------------------------------
    def extract_dynamic_entities(self, text: str) -> dict[str, list[str]]:
        """Delegate to the KeywordPatternRegistry if dynamic regex is enabled."""
        if not self.enable_dynamic_regex:
            return {}
        return self.pattern_registry.extract_all(text)

    # ------------------------------------------------------------------
    # Semantic keyword extraction
    # ------------------------------------------------------------------
    def extract_semantic_keywords(
        self,
        text: str,
        *,
        chunk_size: int = 512,
    ) -> list[SemanticHit]:
        """
        Split *text* into sentences/chunks, embed them, and find keyword
        hits via cosine similarity against keyword embeddings.
        """
        if not self.thread_keywords or self._keyword_embeddings is None:
            return []

        chunks = self.tokenizer.tokenize_sentences(text, max_tokens=chunk_size)
        if not chunks:
            return []

        chunk_embeddings = self.model.encode(
            chunks,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        chunk_norms = np.linalg.norm(chunk_embeddings, axis=1, keepdims=True)
        chunk_norms[chunk_norms == 0] = 1.0
        chunk_embeddings = chunk_embeddings / chunk_norms

        similarities = cosine_similarity(chunk_embeddings, self._keyword_embeddings)
        # similarities shape: (n_chunks, n_keywords)

        hits: list[SemanticHit] = []
        for kw_idx, kw in enumerate(self.thread_keywords):
            chunk_scores = similarities[:, kw_idx]
            best_chunk_idx = int(chunk_scores.argmax())
            best_score = float(chunk_scores[best_chunk_idx])

            if best_score >= self.similarity_threshold:
                context = chunks[best_chunk_idx]
                hits.append(
                    SemanticHit(
                        keyword=kw,
                        score=round(best_score, 6),
                        context=context[:200],
                    )
                )

        # Sort by descending score
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits

    # ------------------------------------------------------------------
    # Key sentence extraction
    # ------------------------------------------------------------------
    def extract_key_sentences(
        self,
        text: str,
        *,
        top_n: int = 5,
    ) -> list[SentenceScore]:
        """
        Split *text* into sentences, score each by max cosine similarity
        to keyword embeddings, and return the top *top_n*.
        """
        if not self.thread_keywords or self._keyword_embeddings is None:
            return []

        raw_sentences = [
            s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip() and len(s.strip()) > 30
        ]
        if not raw_sentences:
            return []

        sent_embeddings = self.model.encode(
            raw_sentences,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        sent_norms = np.linalg.norm(sent_embeddings, axis=1, keepdims=True)
        sent_norms[sent_norms == 0] = 1.0
        sent_embeddings = sent_embeddings / sent_norms

        similarities = cosine_similarity(sent_embeddings, self._keyword_embeddings)
        max_scores = similarities.max(axis=1)

        scored: list[tuple[str, float]] = [
            (sent, float(score)) for sent, score in zip(raw_sentences, max_scores, strict=False)
        ]
        scored.sort(key=lambda x: x[1], reverse=True)

        return [
            SentenceScore(sentence=sent, score=round(score, 6)) for sent, score in scored[:top_n]
        ]

    # ------------------------------------------------------------------
    # Keyword positions
    # ------------------------------------------------------------------
    def extract_keywords_with_positions(self, text: str) -> list[dict[str, Any]]:
        """Use the stemmer's compiled pattern to find all keyword matches with positions."""
        if not self.stemmer.compiled_pattern:
            return []

        results: list[dict[str, Any]] = []
        seen_spans: set[tuple[int, int]] = set()

        for match in self.stemmer.compiled_pattern.finditer(text):
            start = match.start()
            end = match.end()
            if (start, end) in seen_spans:
                continue
            seen_spans.add((start, end))

            matched_text = match.group(0)
            # Determine which keyword this match corresponds to
            keyword = matched_text
            for kw in self.thread_keywords:
                if kw.lower() in matched_text.lower() or matched_text.lower() in kw.lower():
                    keyword = kw
                    break

            category = self.keyword_categories.get(keyword, KeywordCategory.GENERAL)
            results.append(
                {
                    "keyword": keyword,
                    "match": matched_text,
                    "start": start,
                    "end": end,
                    "category": category.value,
                }
            )

        return results

    # ------------------------------------------------------------------
    # Keyword statistics
    # ------------------------------------------------------------------
    def get_keyword_stats(self) -> KeywordStats:
        """Return a KeywordStats Pydantic model with current keyword breakdowns."""
        category_counts: dict[str, int] = {}
        for kw in self.thread_keywords:
            cat = self.keyword_categories.get(kw, KeywordCategory.GENERAL)
            category_counts[cat.value] = category_counts.get(cat.value, 0) + 1

        top_kw = self.top_keywords(10)

        return KeywordStats(
            total_keywords=len(self.thread_keywords),
            total_categories=len(category_counts),
            category_counts=category_counts,
            top_keywords=top_kw,
            stem_mode=self.stemmer.stem_mode.value,
            case_sensitive=self.stemmer.case_sensitive,
            custom_suffixes=tuple(self.stemmer.custom_suffixes),
            last_updated=format_timestamp(datetime.now(UTC)),
        )

    # ------------------------------------------------------------------
    # Master extraction pipeline
    # ------------------------------------------------------------------
    def extract(
        self,
        text: str,
        *,
        update_keywords: bool = True,
    ) -> ExtractResult:
        """Run the full extraction pipeline and return an ExtractResult."""
        word_count = len(text.split())
        input_hash = compute_text_hash(text)

        # Optional dynamic keyword expansion
        newly_expanded: list[str] = []
        if update_keywords:
            newly_expanded = self.update_thread_keywords(text)

        # Ensure keyword embeddings are ready
        if self._keyword_embeddings is None and self.thread_keywords:
            self._recompute_keyword_embeddings()

        # Run all extractors
        regex_entities = self.extract_regex_entities(text)
        dynamic_keyword_matches = self.extract_dynamic_entities(text)
        semantic_keywords = self.extract_semantic_keywords(text)
        key_sentences = self.extract_key_sentences(text, top_n=self.top_k)
        keyword_stats = self.get_keyword_stats()

        return ExtractResult(
            timestamp=format_timestamp(datetime.now(UTC)),
            input_hash=input_hash,
            word_count=word_count,
            regex_entities=regex_entities,
            dynamic_keyword_matches=dynamic_keyword_matches,
            semantic_keywords=semantic_keywords,
            key_sentences=key_sentences,
            newly_expanded_keywords=newly_expanded,
            total_tracked_keywords=len(self.thread_keywords),
            keyword_stats=keyword_stats,
        )

    # ------------------------------------------------------------------
    # Markdown output
    # ------------------------------------------------------------------
    def save_results_to_markdown(
        self,
        result: ExtractResult,
        filename: str = "insights_extracted.md",
    ) -> Path:
        """Format *result* as Markdown and write to *self.output_dir / filename*."""
        md_path = self.output_dir / filename
        ts = result.timestamp

        lines: list[str] = [
            "# Insight Extraction Results\n",
            f"**Generated:** {ts}",
            f"**Input Hash:** {result.input_hash}",
            f"**Word Count:** {result.word_count}",
            f"**Total Tracked Keywords:** {result.total_tracked_keywords}",
            "\n---\n",
        ]

        # Regex Entities
        lines.append("## Regex Entities\n")
        if result.regex_entities:
            for entity_type, matches in result.regex_entities.items():
                lines.append(f"### {entity_type}\n")
                for m in matches:
                    lines.append(f"- {m}")
                lines.append("")
        else:
            lines.append("*No regex entities found.*\n")

        # Dynamic Keyword Matches
        lines.append("## Dynamic Keyword Matches\n")
        if result.dynamic_keyword_matches:
            for entity_type, matches in result.dynamic_keyword_matches.items():
                lines.append(f"### {entity_type}\n")
                for m in matches:
                    lines.append(f"- {m}")
                lines.append("")
        else:
            lines.append("*No dynamic keyword matches found.*\n")

        # Semantic Keywords
        lines.append("## Semantic Keywords\n")
        lines.append("| Keyword | Score | Context |")
        lines.append("|---------|-------|---------|")
        if result.semantic_keywords:
            for hit in result.semantic_keywords:
                ctx = hit.context[:120].replace("|", "\\|")
                lines.append(f"| {hit.keyword} | {hit.score:.4f} | {ctx} |")
        else:
            lines.append("| — | — | — |")
        lines.append("")

        # Key Sentences
        lines.append("## Key Sentences\n")
        lines.append("| Score | Sentence |")
        lines.append("|-------|----------|")
        if result.key_sentences:
            for s in result.key_sentences:
                sent = s.sentence[:200].replace("|", "\\|")
                lines.append(f"| {s.score:.4f} | {sent} |")
        else:
            lines.append("| — | — |")
        lines.append("")

        # Newly Expanded Keywords
        lines.append("## Newly Expanded Keywords\n")
        if result.newly_expanded_keywords:
            lines.append(", ".join(result.newly_expanded_keywords))
        else:
            lines.append("*No new keywords expanded.*")
        lines.append("")

        # Keyword Statistics
        stats = result.keyword_stats
        lines.append("## Keyword Statistics\n")
        lines.append(f"- **Total Keywords:** {stats.total_keywords}")
        lines.append(f"- **Categories:** {json.dumps(stats.category_counts)}")
        lines.append(f"- **Top Keywords:** {stats.top_keywords}")
        lines.append(f"- **Stem Mode:** {stats.stem_mode}")
        lines.append(f"- **Case Sensitive:** {stats.case_sensitive}")

        md_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report written to %s", md_path)
        return md_path

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------
    def save_state(self, path: str | Path = "insight_extractor_state.json") -> None:
        """Persist keyword bank, frequencies, and categories to JSON."""
        if isinstance(path, str):
            warnings.warn(
                "Passing a string path is deprecated; use Path instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        p = (
            self.output_dir / path
            if isinstance(path, str) and not Path(path).is_absolute()
            else Path(path)
        )

        state = {
            "thread_keywords": self.thread_keywords,
            "keyword_freq": dict(self.keyword_freq),
            "keyword_categories": {k: v.value for k, v in self.keyword_categories.items()},
            "stem_mode": self.stem_mode.value,
            "similarity_threshold": self.similarity_threshold,
            "model_name": self.model_name,
            "version": 1,
        }
        p.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("State saved to %s", p)

    def load_state(self, path: str | Path = "insight_extractor_state.json") -> bool:
        """Restore keyword bank, frequencies, and categories from JSON."""
        if isinstance(path, str):
            warnings.warn(
                "Passing a string path is deprecated; use Path instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        p = (
            self.output_dir / path
            if isinstance(path, str) and not Path(path).is_absolute()
            else Path(path)
        )

        if not p.exists():
            logger.debug("State file not found at %s; starting fresh.", p)
            return False

        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise StateLoadError(f"Failed to load state from {p}: {exc}") from exc

        self.thread_keywords = list(raw.get("thread_keywords", []))
        self.keyword_freq = Counter(raw.get("keyword_freq", {}))
        loaded_cats = raw.get("keyword_categories", {})
        self.keyword_categories = {k: KeywordCategory(v) for k, v in loaded_cats.items()}

        # Restore settings if present
        if "stem_mode" in raw:
            self.stem_mode = StemMode(raw["stem_mode"])
        if "similarity_threshold" in raw:
            self.similarity_threshold = float(raw["similarity_threshold"])

        # Re-sync stemmer and registry
        if self.thread_keywords:
            self.stemmer.set_keywords(self.thread_keywords)
            self.pattern_registry.regenerate_dynamic_patterns(self.thread_keywords)
            self._recompute_keyword_embeddings()

        logger.info("State loaded from %s (%d keywords)", p, len(self.thread_keywords))
        return True

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------
    def top_keywords(self, n: int = 20) -> list[tuple[str, int]]:
        """Return the *n* most common keywords by frequency."""
        return self.keyword_freq.most_common(n)
