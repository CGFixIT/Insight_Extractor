from __future__ import annotations

from enum import StrEnum
from typing import final


@final
class StemMode(StrEnum):
    EXACT = "exact"
    STEM = "stem"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    FUZZY = "fuzzy"
    REGEX = "regex"


@final
class KeywordCategory(StrEnum):
    THREAT_INTEL = "threat_intel"
    OSINT = "osint"
    CHILD_SAFETY = "child_safety"
    AI_INFRA = "ai_infra"
    INFOSEC = "infosec"
    GENERAL = "general"


@final
class PatternLabel(StrEnum):
    CVE_ID = "CVE_ID"
    IP_ADDRESS = "IP_ADDRESS"
    HASH_SHA256 = "HASH_SHA256"
    HASH_MD5 = "HASH_MD5"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    BTC_WALLET = "BTC_WALLET"
    RANSOM_AMOUNT = "RANSOM_AMOUNT"
    FILE_EXTENSION = "FILE_EXTENSION"
    DARK_WEB = "DARK_WEB"
    TELEGRAM_HANDLE = "TELEGRAM_HANDLE"
    PORT_NUMBER = "PORT_NUMBER"
    TB_GB_DATA = "TB_GB_DATA"
    YEAR = "YEAR"
    PERCENTAGE = "PERCENTAGE"
    DYNAMIC_KEYWORD = "DYNAMIC_KEYWORD"
