from __future__ import annotations

import urllib.parse
from collections.abc import Sequence

from enpass_escape.models import DeduplicationResult, DuplicatePolicy, Entry


def _content_key(entry: Entry) -> tuple[object, ...]:
    return (
        entry.title,
        entry.url,
        entry.username,
        entry.password,
        entry.notes,
        entry.totp,
        entry.extra_notes,
        entry.category,
        entry.favorite,
        entry.folders,
        entry.attachment_count,
    )


def _account_key(entry: Entry) -> tuple[str, str] | None:
    try:
        parts = urllib.parse.urlsplit(entry.url)
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname or not entry.username:
        return None

    scheme = parts.scheme.casefold()
    hostname = parts.hostname.casefold()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    normalized_url = urllib.parse.urlunsplit(
        (scheme, netloc, parts.path or "/", parts.query, "")
    )
    return normalized_url, entry.username.casefold()


def deduplicate(
    entries: Sequence[Entry], policy: DuplicatePolicy = DuplicatePolicy.NEWEST
) -> DeduplicationResult:
    """Remove only duplicates that can be resolved without guessing."""
    if policy == DuplicatePolicy.KEEP:
        return DeduplicationResult(tuple(entries))

    if policy == DuplicatePolicy.EXACT:
        unique: dict[tuple[object, ...], Entry] = {}
        for entry in entries:
            content_key = _content_key(entry)
            current = unique.get(content_key)
            if current is None or (entry.updated_at or -1) > (current.updated_at or -1):
                unique[content_key] = entry
        return DeduplicationResult(tuple(unique.values()), len(entries) - len(unique))

    groups: dict[tuple[str, str], list[tuple[int, Entry]]] = {}
    selected_indices: set[int] = set()
    for index, entry in enumerate(entries):
        if account_key := _account_key(entry):
            groups.setdefault(account_key, []).append((index, entry))
        else:
            selected_indices.add(index)

    removed = 0
    conflicts = 0
    for group in groups.values():
        if len(group) == 1:
            selected_indices.add(group[0][0])
            continue
        if len({_content_key(entry) for _, entry in group}) == 1:
            selected_indices.add(
                max(group, key=lambda item: item[1].updated_at or -1)[0]
            )
            removed += len(group) - 1
            continue
        if all(entry.updated_at is not None for _, entry in group):
            newest_timestamp = max(
                entry.updated_at for _, entry in group if entry.updated_at is not None
            )
            newest = [item for item in group if item[1].updated_at == newest_timestamp]
            if len(newest) == 1:
                selected_indices.add(newest[0][0])
                removed += len(group) - 1
                continue
        selected_indices.update(index for index, _ in group)
        conflicts += 1
    return DeduplicationResult(
        tuple(
            entry for index, entry in enumerate(entries) if index in selected_indices
        ),
        removed,
        conflicts,
    )
