"""Real terminal regressions, including cursor reports and rendered editing state."""

import codecs
import errno
import os
from pathlib import Path
import re
import select
import shlex
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing

if os.name == 'posix':
    import fcntl
    import pty
    import termios

REPO = Path(__file__).resolve().parents[1]
PROMPT = 'argus-test> '


def isolated_environment(home):
    environment = dict(os.environ, HOME=str(home), USERPROFILE=str(home), TERM='xterm-256color',
                       ARGUS_CONFIG_HOME=str(home / 'config'), ARGUS_STATE_HOME=str(home / 'state'),
                       ARGUS_DATA_HOME=str(home / 'data'), XDG_CONFIG_HOME=str(home / 'xdg-config'),
                       XDG_STATE_HOME=str(home / 'xdg-state'), XDG_DATA_HOME=str(home / 'xdg-data'),
                       ARGUS_PROMPT=PROMPT, ARGUS_LOCALE='en')
    for key in ('NO_COLOR', 'PROMPT_TOOLKIT_NO_CPR', 'ARGUS_BROKER_SOCKET', 'ARGUS_BROKER_PUBLIC_KEY'):
        environment.pop(key, None)
    return environment


class TerminalScreen:
    """Small VT test terminal, not an assertion on a renderer's escape spelling.

    The shell talks to a real PTY. This endpoint applies cursor/erase operations
    and answers CPR requests, just as a terminal emulator does. Assertions inspect
    the displayed text and cursor, not incidental output chunk or ANSI boundaries.
    """

    def __init__(self, reply, rows=40, columns=160):
        self.reply = reply
        self.rows, self.columns = rows, columns
        self.lines = [[' '] * columns for _ in range(rows)]
        self.scrollback = []
        self.row = self.column = 0
        self.saved = (0, 0)
        self.pending = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        self.cpr_requests = 0
        self.newlines = 0

    @property
    def current_line(self):
        return ''.join(self.lines[self.row]).rstrip()

    @property
    def text(self):
        return '\n'.join(self.scrollback + [''.join(line).rstrip() for line in self.lines])

    @property
    def at_prompt(self):
        line = ''.join(self.lines[self.row])
        return line[:self.column].endswith(PROMPT) and not line[self.column:].strip()

    def newline(self):
        self.newlines += 1
        self.row += 1
        if self.row == self.rows:
            self.scrollback.append(''.join(self.lines.pop(0)).rstrip())
            self.lines.append([' '] * self.columns)
            self.row -= 1

    def feed(self, data):
        self.pending += self.decoder.decode(data)
        while self.pending:
            char = self.pending[0]
            if char == '\x1b':
                if len(self.pending) < 2:
                    return
                if self.pending[1] == '[':
                    match = re.match(r'\x1b\[([0-?]*)([ -/]*)([@-~])', self.pending)
                    if match is None:
                        return
                    self.pending = self.pending[match.end():]
                    self.csi(match[1], match[3])
                    continue
                if self.pending[1] == ']':
                    end = re.search(r'\x07|\x1b\\', self.pending[2:])
                    if end is None:
                        return
                    self.pending = self.pending[2 + end.end():]
                    continue
                if self.pending[1] in '78':
                    if self.pending[1] == '7':
                        self.saved = self.row, self.column
                    else:
                        self.row, self.column = self.saved
                # Character-set selection has one additional designator byte.
                consumed = 3 if self.pending[1] in '()' else 2
                if len(self.pending) < consumed:
                    return
                self.pending = self.pending[consumed:]
                continue
            self.pending = self.pending[1:]
            if char == '\r':
                self.column = 0
            elif char == '\n':
                self.newline()
            elif char == '\b':
                self.column = max(0, self.column - 1)
            elif char == '\t':
                self.column = min(self.columns - 1, (self.column // 8 + 1) * 8)
            elif char >= ' ' and char != '\x7f':
                if self.column == self.columns:
                    self.column = 0
                    self.newline()
                self.lines[self.row][self.column] = char
                self.column += 1

    def csi(self, parameters, command):
        private = parameters.startswith(('?', '>'))
        values = [int(value or 0) for value in parameters.lstrip('?>').split(';')]
        amount = values[0] or 1
        if command == 'n' and values[0] == 6:
            self.cpr_requests += 1
            self.reply(f'\x1b[{self.row + 1};{self.column + 1}R'.encode())
        elif private:
            return  # Cursor visibility, bracketed paste, and other terminal modes.
        elif command == 'A':
            self.row = max(0, self.row - amount)
        elif command == 'B':
            self.row = min(self.rows - 1, self.row + amount)
        elif command == 'C':
            self.column = min(self.columns - 1, self.column + amount)
        elif command == 'D':
            self.column = max(0, self.column - amount)
        elif command in ('E', 'F'):
            self.row = max(0, min(self.rows - 1, self.row + (amount if command == 'E' else -amount)))
            self.column = 0
        elif command in ('G', '`'):
            self.column = min(self.columns - 1, amount - 1)
        elif command in ('H', 'f'):
            self.row = min(self.rows - 1, amount - 1)
            self.column = min(self.columns - 1, (values[1] or 1) - 1) if len(values) > 1 else 0
        elif command == 'd':
            self.row = min(self.rows - 1, amount - 1)
        elif command == 'K':
            start, end = ((0, self.columns) if values[0] == 2 else
                          (0, self.column + 1) if values[0] == 1 else (self.column, self.columns))
            self.lines[self.row][start:end] = [' '] * (end - start)
        elif command == 'J':
            if values[0] in (2, 3):
                self.lines = [[' '] * self.columns for _ in range(self.rows)]
            elif values[0] == 0:
                self.lines[self.row][self.column:] = [' '] * (self.columns - self.column)
                for row in range(self.row + 1, self.rows):
                    self.lines[row] = [' '] * self.columns
        elif command == 'P':
            line = self.lines[self.row]
            del line[self.column:self.column + amount]
            line.extend([' '] * (self.columns - len(line)))
        elif command == 'X':
            end = min(self.columns, self.column + amount)
            self.lines[self.row][self.column:end] = [' '] * (end - self.column)
        elif command == '@':
            line = self.lines[self.row]
            line[self.column:self.column] = [' '] * amount
            del line[self.columns:]
        elif command == 's':
            self.saved = self.row, self.column
        elif command == 'u':
            self.row, self.column = self.saved


@unittest.skipUnless(os.name == 'posix', 'Unix PTY required')
class TerminalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.exited = False
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 160, 0, 0))
            os.chdir(self.home)
            os.execve(sys.executable, [sys.executable, str(REPO / 'argus_shell.py'), '--norc', '--locale', 'en'],
                      isolated_environment(self.home))
        self.screen = TerminalScreen(lambda data: os.write(self.master, data))
        self.addCleanup(self.cleanup)
        self.read_until(lambda: self.screen.at_prompt)
        self.assertGreater(self.screen.cpr_requests, 0, 'PTY endpoint must answer real terminal cursor reports')
        self.assertNotIn('terminal does not support cursor position requests', self.screen.text.lower())

    def cleanup(self):
        if not self.exited:
            try:
                os.write(self.master, b'\x03exit\r')
            except OSError:
                pass
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    if os.waitpid(self.pid, os.WNOHANG)[0]:
                        self.exited = True
                        break
                except ChildProcessError:
                    self.exited = True
                    break
                time.sleep(.01)
            if not self.exited:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
        os.close(self.master)
        self.temporary.cleanup()

    def read_until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], .05)[0]:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                self.screen.feed(chunk)
                if predicate():
                    return self.screen.text
        self.fail('PTY timed out or exited; rendered screen:\n' + self.screen.text)

    def accept(self, keys):
        newlines = self.screen.newlines
        os.write(self.master, keys)
        return self.read_until(lambda: self.screen.newlines > newlines and self.screen.at_prompt)

    def command(self, source):
        return self.accept((source + '\r').encode())

    def wait_foreground_child(self, expected_pgid=None):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pgid = os.tcgetpgrp(self.master)
            if pgid > 0 and pgid != self.pid and (expected_pgid is None or pgid == expected_pgid):
                return pgid
            time.sleep(.01)
        self.fail('child did not receive terminal ownership')

    def rows(self):
        with closing(sqlite3.connect(self.home / 'state' / 'argus.db')) as connection:
            return connection.execute('SELECT command,state,exit_status FROM command_audit').fetchall()

    def history(self):
        import json
        return [entry['text'] for entry in json.loads((self.home / 'state' / 'history.json').read_text())['entries']]

    def test_idle_completion_preserves_partially_edited_input(self):
        self.command('sleep 0.5 &')
        source = "printf 'preserved-line\\n'"
        os.write(self.master, source.encode())
        notification = self.read_until(lambda: 'Done sleep 0.5' in self.screen.text
                                       and self.screen.current_line == PROMPT + source)
        self.assertIn('Done sleep 0.5', notification)
        self.assertIn(('sleep 0.5', 'completed', 0), self.rows())
        output = self.accept(b'\r')
        self.assertIn('preserved-line', output.splitlines())
        self.assertIn((source, 'completed', 0), self.rows())

    def test_prompt_cancel_and_stop_resume_preserve_real_job_outcome(self):
        os.write(self.master, b'printf cancelled-input')
        self.read_until(lambda: self.screen.current_line == PROMPT + 'printf cancelled-input')
        self.accept(b'\x03')
        self.assertFalse(any('cancelled-input' in row[0] for row in self.rows()))
        os.write(self.master, b'sleep 10\r')
        pgid = self.wait_foreground_child()
        stopped = self.accept(b'\x1a')
        number = re.search(r'\[(\d+)\] Stopped', stopped).group(1)
        self.assertIn(('sleep 10', 'stopped', None), self.rows())
        self.command('bg %' + number)
        foreground = 'fg %' + number
        newlines = self.screen.newlines
        os.write(self.master, (foreground + '\r').encode())
        # Reading the accepted line prevents a stale PTY group observation from
        # sending Ctrl-C before the editor has submitted the foreground command.
        self.read_until(lambda: self.screen.newlines > newlines
                        and PROMPT + foreground in self.screen.text)
        self.wait_foreground_child(pgid)
        os.write(self.master, b'\x03')
        self.read_until(lambda: self.screen.at_prompt
                        and ('sleep 10', 'completed', 130) in self.rows())
        matching = [row for row in self.rows() if row[0] == 'sleep 10']
        self.assertEqual(matching, [('sleep 10', 'completed', 130)])

    def test_real_tab_completion_multiline_history_and_private_mode(self):
        (self.home / 'space file').write_text('contents')
        output = self.accept(b"printf '<%s>\\n' spa\t\r")
        self.assertIn('<space file>', output.splitlines())
        source = 'for word in first second; do\nprintf "%s\\n" "$word"\ndone'
        output = self.accept((source.replace('\n', '\r') + '\r').encode())
        self.assertIn('first', output.splitlines())
        self.assertIn('second', output.splitlines())
        self.assertIn(source, self.history())
        self.command("printf 'history-recalled\\n'")
        self.accept(b'\x1b[A\r')
        recalled = [row for row in self.rows() if row[0] == "printf 'history-recalled\\n'"]
        self.assertEqual(len(recalled), 2)
        self.command('history private on')
        self.command('printf private-value')
        self.command('history private off')
        self.command('printf public-value')
        self.assertNotIn('printf private-value', self.history())
        self.assertIn('printf public-value', self.history())
        self.assertNotIn('terminal does not support cursor position requests', self.screen.text.lower())


class NoninteractiveHistoryTests(unittest.TestCase):
    def test_command_script_source_and_redirected_stdin_do_not_create_interactive_history(self):
        scenarios = ('command', 'script', 'source', 'stdin')
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                script = home / 'commands.argus'
                script.write_text("printf 'noninteractive-output\\n'\n")
                arguments = [sys.executable, str(REPO / 'argus_shell.py'), '--norc']
                kwargs = {}
                if scenario == 'command':
                    arguments += ['-c', script.read_text()]
                elif scenario == 'script':
                    arguments += [str(script)]
                elif scenario == 'source':
                    arguments += ['-c', 'source ' + shlex.quote(str(script))]
                else:
                    kwargs['input'] = script.read_text()
                result = subprocess.run(arguments, cwd=home, env=isolated_environment(home),
                                        text=True, capture_output=True, timeout=15, **kwargs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('noninteractive-output', result.stdout)
                self.assertFalse((home / 'state' / 'history.json').exists())
                self.assertFalse((home / '.argus_history').exists())


if __name__ == '__main__':
    unittest.main()
