from __future__ import annotations

import csv
import os
import re
import tempfile
import urllib.parse
import warnings
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path

from enpass_escape.models import Entry


APPLE_CSV_HEADER = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]
GOOGLE_CSV_HEADER = ["url", "username", "password", "note"]
BITWARDEN_CSV_HEADER = [
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
]
GOOGLE_IMPORT_LIMIT = 3_000
BITWARDEN_IMPORT_LIMIT = 40_000


def generate_otpauth_url(secret_key: str, title: str = "", username: str = "") -> str:
    """Return an otpauth URI for an Enpass TOTP secret."""
    if not secret_key:
        return ""
    if secret_key.casefold().startswith("otpauth://"):
        return secret_key

    cleaned_secret = secret_key.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z2-7=]+", cleaned_secret):
        warnings.warn(
            f"TOTP secret for '{title or username}' contains invalid Base32 characters",
            stacklevel=2,
        )

    issuer = title.strip()
    account = username.strip()
    label = (
        f"{issuer}:{account}"
        if issuer and account
        else account or issuer or "UnknownAccount"
    )
    params = {
        "secret": cleaned_secret,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
    if issuer:
        params["issuer"] = issuer
    return (
        f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"
    )


def _write_csv(
    output_filepath: str | Path,
    header: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    force: bool = False,
) -> None:
    output = Path(output_filepath)
    if output.exists() and not force:
        raise FileExistsError(f"Output already exists: {output}")
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    try:
        with os.fdopen(
            file_descriptor, "w", newline="", encoding="utf-8"
        ) as destination:
            writer = csv.writer(destination)
            writer.writerow(header)
            writer.writerows(rows)
        os.replace(temporary_name, output)
        os.chmod(output, 0o600)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _notes(entry: Entry) -> str:
    return "\n".join(part for part in (entry.notes, *entry.extra_notes) if part)


def write_apple_csv(
    entries: Iterable[Entry], output_filepath: str | Path, *, force: bool = False
) -> None:
    _write_csv(
        output_filepath,
        APPLE_CSV_HEADER,
        (
            (
                entry.title,
                entry.url,
                entry.username,
                entry.password,
                _notes(entry),
                generate_otpauth_url(entry.totp, entry.title, entry.username),
            )
            for entry in entries
        ),
        force=force,
    )


def google_website_entries(
    entries: Iterable[Entry],
) -> tuple[list[Entry], Counter[str]]:
    """Keep credentials that Google can import as website passwords."""
    accepted: list[Entry] = []
    skipped: Counter[str] = Counter()
    for entry in entries:
        if not entry.password:
            skipped["missing password"] += 1
            continue
        try:
            url = urllib.parse.urlsplit(entry.url)
        except ValueError:
            url = urllib.parse.SplitResult("", "", "", "", "")
        if url.scheme.casefold() not in {"http", "https"} or not url.hostname:
            skipped["invalid website URL"] += 1
            continue
        accepted.append(entry)
    return accepted, skipped


def _google_note(entry: Entry) -> str:
    return "\n".join(
        part
        for part in (f"Title: {entry.title}" if entry.title else "", entry.notes)
        if part
    )


def _write_chunked_csv(
    entries: Sequence[Entry],
    output_filepath: str | Path,
    header: Sequence[str],
    row_factory: Callable[[Entry], Sequence[str]],
    limit: int,
    *,
    force: bool = False,
) -> tuple[Path, ...]:
    output = Path(output_filepath)
    chunks = [
        entries[index : index + limit] for index in range(0, len(entries), limit)
    ] or [[]]
    if len(chunks) == 1:
        paths = [output]
    else:
        suffix = output.suffix or ".csv"
        stem = output.stem if output.suffix else output.name
        paths = [
            output.with_name(f"{stem}-{index}{suffix}")
            for index in range(1, len(chunks) + 1)
        ]

    existing = [path for path in paths if path.exists()]
    if existing and not force:
        raise FileExistsError(f"Output already exists: {existing[0]}")

    # ponytail: multi-part exports are atomic per file; add batch rollback only if partial disk failures matter.
    for path, chunk in zip(paths, chunks, strict=True):
        _write_csv(
            path,
            header,
            (row_factory(entry) for entry in chunk),
            force=force,
        )
    return tuple(paths)


def write_google_csv(
    entries: Sequence[Entry], output_filepath: str | Path, *, force: bool = False
) -> tuple[Path, ...]:
    """Write Google Password Manager CSV files, splitting at its import limit."""
    return _write_chunked_csv(
        entries,
        output_filepath,
        GOOGLE_CSV_HEADER,
        lambda entry: (
            entry.url,
            entry.username,
            entry.password,
            _google_note(entry),
        ),
        GOOGLE_IMPORT_LIMIT,
        force=force,
    )


def _bitwarden_type(entry: Entry) -> str:
    if entry.category.casefold() in {"login", "password"}:
        return "login"
    if not entry.category and any(
        (entry.url, entry.username, entry.password, entry.totp)
    ):
        return "login"
    return "note"


def _bitwarden_row(entry: Entry) -> tuple[str, ...]:
    item_type = _bitwarden_type(entry)
    multiple_folders = (
        f"Enpass folders: {', '.join(entry.folders)}" if len(entry.folders) > 1 else ""
    )
    if item_type == "login":
        notes = entry.notes
        fields = "\n".join(
            part for part in (*entry.extra_notes, multiple_folders) if part
        )
        login = (entry.url, entry.username, entry.password, entry.totp)
    else:
        credentials = (
            f"URL: {entry.url}" if entry.url else "",
            f"Username: {entry.username}" if entry.username else "",
            f"Password: {entry.password}" if entry.password else "",
            f"TOTP: {entry.totp}" if entry.totp else "",
        )
        notes = "\n".join(
            part
            for part in (
                entry.notes,
                *credentials,
                *entry.extra_notes,
                multiple_folders,
            )
            if part
        )
        fields = ""
        login = ("", "", "", "")
    return (
        entry.folders[0] if len(entry.folders) == 1 else "",
        "1" if entry.favorite else "",
        item_type,
        entry.title or "Untitled",
        notes,
        fields,
        "0",
        *login,
    )


def write_bitwarden_csv(
    entries: Sequence[Entry], output_filepath: str | Path, *, force: bool = False
) -> tuple[Path, ...]:
    """Write personal-vault Bitwarden CSV files."""
    return _write_chunked_csv(
        entries,
        output_filepath,
        BITWARDEN_CSV_HEADER,
        _bitwarden_row,
        BITWARDEN_IMPORT_LIMIT,
        force=force,
    )


def write_apple_csv_from_dicts(
    dicts: Iterable[Mapping[str, object]],
    output_filepath: str | Path,
    *,
    force: bool = False,
) -> None:
    """Compatibility wrapper for the original public helper."""

    def from_mapping(item: Mapping[str, object]) -> Entry:
        raw_extra_notes = item.get("_extra", [])
        extra_notes = (
            tuple(str(note) for note in raw_extra_notes)
            if isinstance(raw_extra_notes, (list, tuple))
            else ()
        )
        return Entry(
            title=str(item.get("Title", "")),
            url=str(item.get("URL", "")),
            username=str(item.get("Username", "")),
            password=str(item.get("Password", "")),
            notes=str(item.get("Notes", "")),
            totp=str(item.get("TOTP", "")),
            extra_notes=extra_notes,
        )

    entries = (from_mapping(item) for item in dicts)
    write_apple_csv(entries, output_filepath, force=force)
