from datetime import timezone

import pytest

from tracekc.timeutil import timestamp


def test_shared_timestamp_normalizes_offsets_to_utc():
    assert timestamp('2026-11-01T05:30:00+05:30') == timestamp('2026-11-01T00:00:00Z')
    assert timestamp('2026-11-01T00:00:00Z').tzinfo == timezone.utc


@pytest.mark.parametrize('value', ['2026-11-01T00:00:00', '2026-11-01'])
def test_shared_timestamp_rejects_timezone_free_values(value):
    with pytest.raises(ValueError, match='timezone'):
        timestamp(value)
