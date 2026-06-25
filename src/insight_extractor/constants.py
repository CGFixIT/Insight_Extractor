"""Static data constants for insight_extractor."""
from __future__ import annotations

from insight_extractor.config import PatternLabel

type RegexPatternDict = dict[str, str]
type KeywordList = list[str]

THREAD_SEEDS: KeywordList = [
    # Ransomware / threat intel
    "ransomware", "nitrogen", "foxconn", "ESXi", "conti", "ALPHV", "blackcat",
    "RaaS", "double extortion", "supply chain", "data breach", "exfiltration",
    "payload", "loader", "YARA", "veeam", "watchtowr", "CVE",
    # OSINT / identity
    "OSINT", "data broker", "NPD", "national public data", "SSN", "dox",
    "facial recognition", "biometric", "SIM swap", "credential reset",
    "identity theft", "breach data",
    # Child safety / predators
    "predator", "Roblox", "CSAM", "grooming", "blackmail", "coercion",
    "age verification", "Discord", "Telegram", "minor", "sextortion",
    # PsyClaw / AI infra
    "PsyClaw", "LangGraph", "ChromaDB", "BM25", "RRF", "RAG",
    "soul", "personality", "sanitizer", "telemetry", "offline",
    "BERT", "embedding", "semantic search", "hybrid retrieval",
    # InfoSec / general
    "zero-day", "exploit", "phishing", "malware", "APT", "threat actor",
    "lateral movement", "privilege escalation", "encryption", "decryption",
    "public key", "private key", "cryptographic",
]

REGEX_PATTERNS: RegexPatternDict = {
    PatternLabel.CVE_ID:          r"CVE-\d{4}-\d{4,7}",
    PatternLabel.IP_ADDRESS:      r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    PatternLabel.HASH_SHA256:     r"\b[0-9a-fA-F]{64}\b",
    PatternLabel.HASH_MD5:        r"\b[0-9a-fA-F]{32}\b",
    PatternLabel.DOMAIN:          r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|edu|onion|xyz|co)\b",
    PatternLabel.EMAIL:           r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    PatternLabel.BTC_WALLET:      r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    PatternLabel.RANSOM_AMOUNT:   r"\$\s?\d[\d,]*(?:\.\d{2})?\s?(?:million|billion|M|B|k)?",
    PatternLabel.FILE_EXTENSION:  r"\.\b(?:exe|dll|ps1|bat|sh|py|bin|enc|locked)\b",
    PatternLabel.DARK_WEB:        r"\b\w+\.onion\b",
    PatternLabel.TELEGRAM_HANDLE: r"@[A-Za-z0-9_]{5,}",
    PatternLabel.PORT_NUMBER:     r"\bport\s+(\d{2,5})\b",
    PatternLabel.TB_GB_DATA:      r"\b\d+(?:\.\d+)?\s?(?:TB|GB|MB|terabyte|gigabyte)\b",
    PatternLabel.YEAR:            r"\b20[12]\d\b",
    PatternLabel.PERCENTAGE:      r"\b\d+(?:\.\d+)?%",
}
