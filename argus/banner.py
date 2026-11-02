"""Bounded, terminal-aware startup styling; never reads or discards user input."""

import os
import shutil
import sys
import textwrap
import time

from . import __version__
from .i18n import translate
from .terminal import TerminalCapabilities

_WORDMARK = (
    ' █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗',
    '██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝',
    '███████║██████╔╝██║  ███╗██║   ██║███████╗',
    '██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║',
    '██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║',
    '╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝',
)
_RESET = '\x1b[0m'


def _gradient(text, *, sweep=None):
    """Use RGB only when advertised; keep 256/16-color terminals compatible."""
    truecolor = os.environ.get('COLORTERM', '').lower() in ('truecolor', '24bit')
    extended = '256color' in os.environ.get('TERM', '')
    colors = (51, 45, 39, 63, 99, 135, 171, 207)
    basic = (96, 96, 94, 94, 95, 95, 95, 95)
    result = []
    for index, character in enumerate(text):
        fraction = index / max(1, len(text) - 1)
        if sweep is not None and abs(index - sweep) < 3:
            color = '\x1b[97;1m'
        elif truecolor:
            red = round(35 + 182 * fraction)
            green = round(218 - 110 * fraction)
            blue = round(239 + 16 * fraction)
            color = f'\x1b[38;2;{red};{green};{blue}m'
        elif extended:
            color = f'\x1b[38;5;{colors[min(7, int(fraction * 8))]}m'
        else:
            color = f'\x1b[{basic[min(7, int(fraction * 8))]}m'
        result.append(color + character)
    return ''.join(result) + _RESET


def show_banner(settings, *, stream=None):
    """Render once, with an optional ~0.2s decorative sweep and no cursor hiding."""
    stream = sys.stdout if stream is None else stream
    capabilities = TerminalCapabilities.detect(settings, stdout=stream)
    locale = settings.get('locale', 'en')
    encoding = getattr(stream, 'encoding', None) or 'utf-8'
    welcome = translate('welcome', locale).encode(encoding, errors='replace').decode(encoding)
    if not capabilities.interactive:
        return
    if not capabilities.color:
        print(f'{welcome}  v{__version__}', file=stream)
        return

    columns = shutil.get_terminal_size(fallback=(80, 24)).columns
    width = min(70, max(1, columns - 4))
    # Unicode art needs a Unicode-capable stream. Legacy console encodings use
    # the same responsive layout with an ASCII wordmark and separator instead.
    try:
        ''.join(_WORDMARK).encode(encoding)
        unicode_art = True
    except (LookupError, UnicodeEncodeError):
        unicode_art = False
    large = unicode_art and width >= max(map(len, _WORDMARK)) + 4
    art = _WORDMARK if large else ('A R G U S' if width >= 9 else 'ARGUS'[:width],)
    margin = '  ' if columns >= 12 else ''
    separator = ('─' if unicode_art else '-') * width

    print(file=stream)
    for row in art:
        print(margin + _gradient(row.center(width)), file=stream)
    for line in textwrap.wrap(f'v{__version__}', width=width):
        print(margin + _gradient(line.center(width)), file=stream)
    # Keep translated subtitles within the actual terminal width as well.
    for line in textwrap.wrap(welcome, width=width):
        print(margin + '\x1b[2m' + line.center(width) + _RESET, file=stream)
    print(file=stream)

    animate = not os.environ.get('ARGUS_NO_ANIMATION')
    try:
        if animate:
            for frame in range(9):
                stream.write('\r' + margin + _gradient(separator, sweep=round((width + 6) * frame / 8) - 3))
                stream.flush()
                time.sleep(0.022)
    except KeyboardInterrupt:
        # Ctrl+C skips the decoration without killing the new interactive shell.
        pass
    finally:
        stream.write(('\r' if animate else '') + margin + _gradient(separator) + '\n')
        stream.flush()
    print(file=stream)
