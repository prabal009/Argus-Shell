"""Presentation boundaries that can otherwise wrap or break terminal startup."""

import io
import os
import unittest
from unittest.mock import patch

from argus.banner import show_banner
from argus.terminal import plain_text


class TerminalBuffer(io.StringIO):
    encoding = 'utf-8'

    def isatty(self):
        return True


class BannerBoundaryTests(unittest.TestCase):
    def test_art_version_and_localized_subtitle_fit_narrow_terminals(self):
        with patch.dict(os.environ, {'TERM': 'xterm-256color', 'ARGUS_NO_ANIMATION': '1'}, clear=True):
            for columns in (1, 4, 8, 20, 32, 50, 80):
                with self.subTest(columns=columns), patch('argus.banner.sys.stdin', TerminalBuffer()), patch(
                    'argus.banner.shutil.get_terminal_size', return_value=os.terminal_size((columns, 24))
                ):
                    output = TerminalBuffer()
                    show_banner({'locale': 'es'}, stream=output)
                    for line in plain_text(output.getvalue()).splitlines():
                        self.assertLessEqual(len(line), columns, repr(line))


if __name__ == '__main__':
    unittest.main()
