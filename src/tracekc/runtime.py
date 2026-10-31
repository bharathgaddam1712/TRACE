"""Temporary execution-state request for uninterrupted local demonstrations."""
from contextlib import contextmanager
import os


@contextmanager
def keep_awake(_setter=None):
    """Hold idle system/display sleep only for this scope; restore the thread state.

    Explicit user sleep/lid actions still take precedence. This does not change
    the saved Windows power plan. See Microsoft's SetThreadExecutionState docs.
    """
    if _setter is None:
        if os.name!='nt':
            yield False
            return
        import ctypes
        _setter=ctypes.windll.kernel32.SetThreadExecutionState
        _setter.argtypes=[ctypes.c_uint];_setter.restype=ctypes.c_uint
    previous=_setter(0x80000003)
    try:
        yield bool(previous)
    finally:
        if previous:_setter(previous|0x80000000)
