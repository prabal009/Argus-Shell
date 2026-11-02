"""Portable terminal capability detection and safe event-loop child notices.

There are no readline/ctypes hooks and no process operations in signal handlers.
The native prompt-toolkit output backend handles Windows consoles and POSIX TTYs.
"""

import asyncio
from collections import deque
from dataclasses import dataclass
import os
import re
import sys

_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')


def plain_text(text):
    """Drop terminal escapes, readline sentinels and unsafe prompt controls."""
    text = _ANSI.sub('', str(text)).replace('\x01', '').replace('\x02', '')
    return ''.join(char for char in text if char >= ' ' or char in '\n\t')


@dataclass(frozen=True)
class TerminalCapabilities:
    interactive: bool
    color: bool
    accessible: bool

    @classmethod
    def detect(cls, settings=None, *, stdin=None, stdout=None):
        settings = settings or {}
        stdin = sys.stdin if stdin is None else stdin
        stdout = sys.stdout if stdout is None else stdout
        interactive = bool(getattr(stdin, 'isatty', lambda: False)()
                           and getattr(stdout, 'isatty', lambda: False)())
        accessible = bool(settings.get('accessibility', False))
        color = (interactive and not accessible and not settings.get('no_color', False)
                 and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb')
        return cls(interactive, color, accessible)


class ChildNotifications:
    """Schedule child polling on the editor loop, preserving its input buffer.

    wake() only schedules a loop callback; callbacks that reap are invoked by the
    loop, never by a signal handler. A small timer also covers native Windows,
    where SIGCHLD and POSIX wakeup pipes do not exist.
    """

    def __init__(self, callback):
        self.callback = callback
        self.loop = None
        self.task = None
        self.pending = False
        self.closed = False
        self.callbacks = deque()

    def wake(self):
        self.pending = True
        loop = self.loop
        if loop is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(self._dispatch)
            except RuntimeError:
                # Prompt's loop can close between the check and the scheduling.
                pass

    def notify(self, callback):
        self.callbacks.append(callback)
        self.wake()

    def _dispatch(self):
        if self.closed or not self.pending:
            return
        self.pending = False
        self.callback()
        while self.callbacks:
            self.callbacks.popleft()()

    def start(self):
        self.loop = asyncio.get_running_loop()
        self.closed = False
        self.task = self.loop.create_task(self._poll())
        if self.pending:
            self.loop.call_soon(self._dispatch)

    async def _poll(self):
        while not self.closed:
            await asyncio.sleep(.1)
            self.pending = True
            self._dispatch()

    def stop(self):
        self.closed = True
        if self.task is not None:
            self.task.cancel()
        self.task = None
        self.loop = None
