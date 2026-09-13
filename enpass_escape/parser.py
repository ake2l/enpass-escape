from __future__ import annotations

import csv
import itertools
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from enpass_escape.models import Entry


ENPASS_FIELD_MAPPINGS: dict[str, tuple[str, ...]] = {
    "Title": ("Title", "Name", "Login name", "ItemName"),
    "URL": ("URL", "Website", "Web Address", "Login URL"),
    "Username": ("Username", "User ID", "Login ID", "Login Username"),
    "Password": ("Password", "*Password", "Passphrase", "Login Password"),
    "TOTP": (
        "TOTP",
        "TOTP Secret",
        "One-Time Password",
        "One-time code",
        "OTP Secret",
        "OTP",
        "TOTP Key",
    ),
    "Notes": ("Note", "Notes", "Description", "Details", "Memo", "My notes"),
}
FIELD_TYPE_MAPPINGS = {
    "url": "URL",
    "username": "Username",
    "password": "Password",
    "totp": "TOTP",
}


def _mapped_field(label: str, field_type: str = "") -> str | None:
    if mapped := FIELD_TYPE_MAPPINGS.get(field_type.casefold()):
        return mapped
    folded_label = label.casefold()
    return next(
        (
            name
            for name, options in ENPASS_FIELD_MAPPINGS.items()
            if folded_label in (option.casefold() for option in options)
        ),
        None,
    )


def _entry_from_fields(
    *,
    title: str,
    notes: str,
    fields: Iterable[Mapping[str, object]],
    category: str = "",
    favorite: bool = False,
    folders: tuple[str, ...] = (),
    attachment_count: int = 0,
    updated_at: int | None = None,
    uuid: str = "",
) -> Entry:
    values: dict[str, str] = {}
    extra_notes: list[str] = []

    for field in fields:
        if field.get("deleted"):
            continue
        label = str(field.get("label", "")).strip()
        raw_value = field.get("value", "")
        if not isinstance(raw_value, str):
            continue
        mapped = _mapped_field(label, str(field.get("type", "")))
        value = raw_value if mapped == "Password" else raw_value.strip()
        if not label or not value:
            continue
        if mapped and mapped not in values:
            values[mapped] = value
        elif field.get("type") != "section":
            extra_notes.append(f"{label}: {value}")

    return Entry(
        title=title,
        url=values.get("URL", ""),
        username=values.get("Username", ""),
        password=values.get("Password", ""),
        notes=notes,
        totp=values.get("TOTP", ""),
        extra_notes=tuple(extra_notes),
        category=category,
        favorite=favorite,
        folders=folders,
        attachment_count=attachment_count,
        updated_at=updated_at,
        uuid=uuid,
    )


def parse_enpass_json(
    input_filepath: str | Path,
    *,
    include_archived: bool = False,
    include_trashed: bool = False,
) -> list[Entry]:
    """Parse an Enpass JSON export into normalized entries."""
    with Path(input_filepath).open(encoding="utf-8") as source:
        data = json.load(source)
    if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
        raise ValueError("Invalid Enpass JSON export")

    raw_folders = data.get("folders", [])
    if not isinstance(raw_folders, list) or not all(
        isinstance(folder, dict) for folder in raw_folders
    ):
        raise ValueError("Invalid folders in Enpass JSON export")
    folder_names = {
        str(folder.get("uuid")): str(folder.get("title", "")).strip()
        for folder in raw_folders
        if folder.get("uuid")
    }

    entries: list[Entry] = []
    for item in data.get("items", []):
        if not isinstance(item, dict):
            raise ValueError("Invalid item in Enpass JSON export")
        if (item.get("archived") and not include_archived) or (
            item.get("trashed") and not include_trashed
        ):
            continue
        fields = item.get("fields", [])
        if not isinstance(fields, list) or not all(
            isinstance(field, dict) for field in fields
        ):
            raise ValueError("Invalid fields in Enpass JSON export")
        attachments = item.get("attachments", [])
        if not isinstance(attachments, list):
            raise ValueError("Invalid attachments in Enpass JSON export")
        folder_ids = item.get("folders") or []
        if not isinstance(folder_ids, list) or not all(
            isinstance(folder_id, str) for folder_id in folder_ids
        ):
            raise ValueError("Invalid item folders in Enpass JSON export")
        timestamp = item.get("updated_at")
        entries.append(
            _entry_from_fields(
                title=str(item.get("title", "")),
                notes=str(item.get("note", "")),
                fields=fields,
                category=str(item.get("category", "")),
                favorite=bool(item.get("favorite")),
                folders=tuple(
                    folder_names.get(folder_id) or folder_id for folder_id in folder_ids
                ),
                attachment_count=len(attachments),
                updated_at=timestamp
                if isinstance(timestamp, int) and not isinstance(timestamp, bool)
                else None,
                uuid=str(item.get("uuid", "")),
            )
        )
    return entries


def _entry_from_key_value_row(row: Sequence[str]) -> Entry:
    fields = (
        {
            "label": row[index].strip(),
            "value": row[index + 1] if index + 1 < len(row) else "",
        }
        for index in range(1, len(row), 2)
    )
    return _entry_from_fields(
        title=row[0].strip() if row else "", notes="", fields=fields
    )


def parse_enpass_csv(input_filepath: str | Path) -> list[Entry]:
    """Parse header-based or Enpass key/value CSV exports."""
    with Path(input_filepath).open(newline="", encoding="utf-8-sig") as source:
        reader = csv.reader(source)
        try:
            first_row = next(reader)
        except StopIteration:
            raise csv.Error("CSV file has no rows") from None
        if not first_row:
            raise csv.Error("CSV file has an empty first row")

        title_labels = {label.casefold() for label in ENPASS_FIELD_MAPPINGS["Title"]}
        if first_row[0].strip().casefold() not in title_labels:
            return [
                _entry_from_key_value_row(row)
                for row in itertools.chain([first_row], reader)
                if any(cell.strip() for cell in row)
            ]

        header = [name.strip() for name in first_row]
        indices = {name.casefold(): index for index, name in enumerate(header)}
        mapped_indices: dict[str, int] = {}
        for name, options in ENPASS_FIELD_MAPPINGS.items():
            for option in options:
                if option.casefold() in indices:
                    mapped_indices[name] = indices[option.casefold()]
                    break

        entries: list[Entry] = []
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            row = [*row, *([""] * max(0, len(header) - len(row)))]

            def value(name: str, *, strip: bool = True) -> str:
                index = mapped_indices.get(name)
                if index is None or index >= len(row):
                    return ""
                return row[index].strip() if strip else row[index]

            used = set(mapped_indices.values())
            extras = tuple(
                f"{header[index]}: {cell.strip()}"
                for index, cell in enumerate(row[: len(header)])
                if index not in used and cell.strip()
            )
            entries.append(
                Entry(
                    title=value("Title"),
                    url=value("URL"),
                    username=value("Username"),
                    password=value("Password", strip=False),
                    notes=value("Notes"),
                    totp=value("TOTP"),
                    extra_notes=extras,
                )
            )
        return entries


def parse_enpass(
    input_filepath: str | Path,
    *,
    include_archived: bool = False,
    include_trashed: bool = False,
) -> list[Entry]:
    suffix = Path(input_filepath).suffix.casefold()
    if suffix == ".json":
        return parse_enpass_json(
            input_filepath,
            include_archived=include_archived,
            include_trashed=include_trashed,
        )
    if suffix == ".csv":
        return parse_enpass_csv(input_filepath)
    raise ValueError("Input must be an Enpass .json or .csv export")
