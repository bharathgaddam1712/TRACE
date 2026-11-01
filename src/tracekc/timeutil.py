"""Timezone-aware timestamp parsing shared by investigation and correlation."""
from datetime import datetime, timezone


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamps must include a timezone')
    return parsed.astimezone(timezone.utc)
