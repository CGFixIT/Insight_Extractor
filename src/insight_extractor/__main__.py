"""CLI entry point for insight_extractor."""
from __future__ import annotations

import sys
from pathlib import Path

from insight_extractor.extractor import InsightExtractor
from insight_extractor.utils import setup_logging


def main() -> None:
    setup_logging()
    extractor = InsightExtractor()
    extractor.load_state()

    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        text = """
        On May 11 2026, the Nitrogen ransomware group claimed to have stolen 8 terabytes
        of data from Foxconn North American facilities including Mount Pleasant Wisconsin.
        The group used leaked Conti 2 builder code targeting VMware ESXi environments.
        Coveware found a critical coding bug in the ESXi encryptor: files are encrypted
        with the wrong public key, making recovery impossible even after paying the ransom.
        Ryan Montgomery demonstrated live OSINT on Tucker Carlson, retrieving SSN and
        driver license number from the National Public Data breach of 2.9 billion records.
        He also showed how Roblox age-verified accounts can be purchased on eBay for
        a few dollars, bypassing facial biometric verification entirely.
        PsyClaw uses BERT embeddings with ChromaDB and BM25 hybrid retrieval via RRF fusion.
        CVE-2026-48710 affects the Starlette framework used in millions of AI agent pipelines.
        """

    results = extractor.extract(text)

    print("\n=== REGEX ENTITIES ===")
    for etype, vals in results.regex_entities.items():
        print(f"  {etype}: {vals}")

    print("\n=== DYNAMIC KEYWORD MATCHES ===")
    for etype, vals in results.dynamic_keyword_matches.items():
        print(f"  {etype}: {vals[:10]}{' ...' if len(vals) > 10 else ''}")

    print("\n=== SEMANTIC KEYWORD HITS (top 10) ===")
    for hit in results.semantic_keywords:
        print(f"  [{hit.score:.3f}] {hit.keyword}")
        print(f"           ...{hit.context[:80]}...")

    print("\n=== KEY SENTENCES ===")
    for s in results.key_sentences:
        print(f"  [{s.score:.3f}] {s.sentence[:120]}")

    print(f"\n=== DYNAMIC EXPANSION: +{len(results.newly_expanded_keywords)} new keywords ===")
    if results.newly_expanded_keywords:
        print(f"  {results.newly_expanded_keywords}")

    print(f"\nTotal tracked keywords: {results.total_tracked_keywords}")

    md_path = extractor.save_results_to_markdown(results)
    print(f"\nResults saved to: {md_path}")

    stats = results.keyword_stats
    print(f"\n=== KEYWORD STATS ===")
    print(f"  Categories: {stats.category_counts}")
    print(f"  Stem mode: {stats.stem_mode}")

    extractor.save_state()


if __name__ == "__main__":
    main()
