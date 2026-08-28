"""Executable accounting for the committed R6A scenario manifest.

Tests mark a scenario only after its assertions have completed successfully.
The bounded suite runner then requires every committed manifest identifier to
have been marked exactly once.  Loading the manifest here avoids a second,
hand-maintained scenario inventory.
"""

from __future__ import annotations

import functools
import json
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Callable, TypeVar, cast


_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST = _ROOT / "fixtures" / "cgam-durable-binding" / "MANIFEST.json"
_manifest_value = json.loads(_MANIFEST.read_text(encoding="utf-8"))
_scenario_ids = _manifest_value.get("scenario_ids")
if (
    not isinstance(_scenario_ids, list)
    or not _scenario_ids
    or len(_scenario_ids) != len(set(_scenario_ids))
    or not all(isinstance(item, str) and item.startswith("R6A-") for item in _scenario_ids)
):
    raise RuntimeError("R6A fixture manifest scenario IDs are missing, duplicate, or malformed")

EXPECTED_SCENARIO_IDS = tuple(_scenario_ids)
EXPECTED_SCENARIO_SET = frozenset(EXPECTED_SCENARIO_IDS)

_lock = threading.Lock()
_declarations: Counter[str] = Counter()
_hits: Counter[str] = Counter()
_F = TypeVar("_F", bound=Callable[..., Any])


def _validate_ids(scenario_ids: tuple[str, ...]) -> None:
    if not scenario_ids or len(scenario_ids) != len(set(scenario_ids)):
        raise AssertionError("scenario instrumentation requires unique non-empty IDs")
    unknown = sorted(set(scenario_ids) - EXPECTED_SCENARIO_SET)
    if unknown:
        raise AssertionError(f"scenario instrumentation contains unknown IDs: {unknown}")


def scenario(*scenario_ids: str) -> Callable[[_F], _F]:
    """Mark the supplied IDs exactly once after a decorated test succeeds."""

    ids = tuple(scenario_ids)
    _validate_ids(ids)
    with _lock:
        _declarations.update(ids)

    def decorate(function: _F) -> _F:
        @functools.wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            result = function(*args, **kwargs)
            for scenario_id in ids:
                pass_scenario(scenario_id)
            return result

        setattr(wrapped, "r6a_scenario_ids", ids)
        return cast(_F, wrapped)

    return decorate


def pass_scenario(scenario_id: str) -> None:
    """Record one successful table/subtest scenario assertion boundary."""

    _validate_ids((scenario_id,))
    with _lock:
        _hits[scenario_id] += 1
        if _hits[scenario_id] > 1:
            raise AssertionError(f"R6A scenario recorded more than once: {scenario_id}")


def reset_hits() -> None:
    """Reset runtime hits without discarding import-time declarations."""

    with _lock:
        _hits.clear()


def accounting() -> dict[str, dict[str, int]]:
    """Return immutable copies of declaration and runtime-hit counters."""

    with _lock:
        return {
            "declarations": dict(_declarations),
            "hits": dict(_hits),
        }
