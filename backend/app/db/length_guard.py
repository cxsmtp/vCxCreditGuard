"""Keep over-long text from the outside world from failing a write.

Names, e-mail addresses and labels arrive from the Checkmarx One API and from
uploaded files, and nothing guarantees they fit the columns they are stored in.
SQLite does not enforce ``VARCHAR(n)``; PostgreSQL does, by raising - and one
over-long display name was enough to abort a whole synchronisation or cycle,
on PostgreSQL only, where the tests never looked.

Descriptive text is therefore trimmed to its column's width as it is assigned.
Identifiers are deliberately left alone: primary keys, foreign keys and columns
under a unique constraint are what rows are matched on, and quietly shortening
one could make two different things look like the same thing. An over-long
identifier still fails, loudly, which is the right outcome for it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import Index, String, UniqueConstraint, event
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

_installed: set[tuple[str, str]] = set()


def _trimmer(table: str, column: str, length: int) -> Callable[..., Any]:
    def trim(_target: Any, value: Any, _oldvalue: Any, _initiator: Any) -> Any:
        if isinstance(value, str) and len(value) > length:
            logger.warning(
                "Value for %s.%s was %d characters and has been trimmed to %d",
                table,
                column,
                len(value),
                length,
            )
            return value[:length]
        return value

    return trim


def _identifying_columns(table: Any) -> set[str]:
    names = {column.name for column in table.columns if column.primary_key or column.unique}
    names |= {column.name for column in table.columns if column.foreign_keys}
    for constraint in table.constraints:
        if isinstance(constraint, UniqueConstraint):
            names |= {column.name for column in constraint.columns}
    for index in table.indexes:
        if isinstance(index, Index) and index.unique:
            names |= {column.name for column in index.columns}
    return names


def install_length_guards(base: type[DeclarativeBase]) -> int:
    """Trim descriptive strings to their column width on assignment. Idempotent."""
    installed = 0
    for mapper in base.registry.mappers:
        table = mapper.local_table
        identifying = _identifying_columns(table)
        for column in table.columns:
            length = getattr(column.type, "length", None)
            if not isinstance(column.type, String) or not length or column.name in identifying:
                continue
            key = (table.name, column.name)
            if key in _installed:
                continue
            attribute = getattr(mapper.class_, mapper.get_property_by_column(column).key)
            event.listen(attribute, "set", _trimmer(table.name, column.name, length), retval=True)
            _installed.add(key)
            installed += 1
    return installed
