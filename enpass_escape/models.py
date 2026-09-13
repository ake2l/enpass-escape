from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Target(StrEnum):
    APPLE = "apple"
    BITWARDEN = "bitwarden"
    GOOGLE = "google"


class DuplicatePolicy(StrEnum):
    KEEP = "keep"
    EXACT = "exact"
    NEWEST = "newest"


@dataclass(frozen=True, slots=True)
class Entry:
    title: str = ""
    url: str = ""
    username: str = ""
    password: str = ""
    notes: str = ""
    totp: str = ""
    extra_notes: tuple[str, ...] = ()
    category: str = ""
    favorite: bool = False
    folders: tuple[str, ...] = ()
    attachment_count: int = 0
    updated_at: int | None = None
    uuid: str = ""


@dataclass(frozen=True, slots=True)
class DeduplicationResult:
    entries: tuple[Entry, ...]
    removed: int = 0
    conflicts: int = 0
