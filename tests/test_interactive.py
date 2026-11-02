"""Consumer-level editor, completion, localization, and durable history behavior."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from argus import i18n
from argus.history import History
from argus.interactive import BashLexer, InteractiveSession, ShellCompleter, _EditorHistory
from argus.language import ShellRuntime, ShellState
from argus.terminal import TerminalCapabilities, plain_text


class InteractiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.previous_directory = Path.cwd()
        os.chdir(self.home)
        self.addCleanup(os.chdir, self.previous_directory)
        previous_locale = i18n._locale
        self.addCleanup(setattr, i18n, '_locale', previous_locale)
        self.environment = patch.dict(os.environ, {'TERM': 'xterm'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.runtime = ShellRuntime(lambda commands, background, runtime: 0,
                                    state=ShellState(variables={'PATH': '', 'HOME': str(self.home)}))
        self.settings = {'history_file': str(self.home / 'history.json'), 'locale': 'en',
                         'prompt': 'test [{status}] > ', 'startup_files': []}

    def completions(self, text, **kwargs):
        completer = ShellCompleter(self.runtime, **kwargs)
        return list(completer.get_completions(Document(text), CompleteEvent(completion_requested=True)))

    def test_completion_uses_live_builtins_functions_aliases_and_path(self):
        executable = self.home / ('feature-external.exe' if os.name == 'nt' else 'feature-external')
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o700)
        (self.home / 'feature-nonexecutable').write_text('not executable')
        self.runtime.state.variables['PATH'] = str(self.home)
        self.runtime.state.functions['feature-function'] = 'feature-function() { :; }'
        self.runtime.state.aliases['feature-alias'] = 'true'
        results = self.completions('feature-', builtins=['feature-builtin'], locale='es')
        categories = {item.display_text: item.display_meta_text for item in results}
        self.assertEqual(categories['feature-builtin'], i18n.translate('completion.builtin', 'es'))
        self.assertEqual(categories['feature-function'], i18n.translate('completion.function', 'es'))
        self.assertEqual(categories['feature-alias'], i18n.translate('completion.alias', 'es'))
        self.assertEqual(categories[executable.name], i18n.translate('completion.command', 'es'))
        self.assertNotEqual(categories.get('feature-nonexecutable'), i18n.translate('completion.command', 'es'))
        self.runtime.state.aliases['feature-new'] = 'true'
        self.assertIn('feature-new', {item.display_text for item in self.completions('feature-')})

    def test_completion_recognizes_command_positions_and_redirection_operands(self):
        for source in ('fea', 'true | fea', 'true && fea', 'true; fea', 'LOCAL=value fea'):
            with self.subTest(source=source):
                self.assertIn('feature-builtin', {item.display_text for item in self.completions(
                    source, builtins=['feature-builtin'])})
        for source in ('printf fea', 'printf > fea', 'printf "fea'):
            with self.subTest(source=source):
                self.assertNotIn('feature-builtin', {item.display_text for item in self.completions(
                    source, builtins=['feature-builtin'])})

    def test_path_completion_quotes_spaces_and_finishes_open_quotes(self):
        (self.home / 'space name.txt').write_text('contents')
        (self.home / 'space directory').mkdir()
        (self.home / '.space-hidden').write_text('hidden')
        for source in ('printf spa', 'printf "spa', "printf 'spa"):
            with self.subTest(source=source):
                results = self.completions(source)
                item = next(item for item in results if item.display_text == 'space name.txt')
                buffer = Buffer(document=Document(source))
                buffer.apply_completion(item)
                self.assertEqual(shlex.split(buffer.text), ['printf', 'space name.txt'])
                self.assertIn('space directory/', {item.display_text for item in results})
                self.assertNotIn('.space-hidden', {item.display_text for item in results})
        self.assertIn('.space-hidden', {item.display_text for item in self.completions('printf .spa')})

    def test_path_completion_uses_shell_variables_not_process_environment(self):
        directory = self.home / 'shell directory'
        directory.mkdir()
        target = directory / 'actual file'
        target.write_text('contents')
        self.runtime.state.variables['PROJECT'] = str(directory)
        with patch.dict(os.environ, {'PROJECT': '/not/the/shell/value'}):
            for source in ('printf $PROJECT/act', 'printf ${PROJECT}/act'):
                with self.subTest(source=source):
                    result = next(item for item in self.completions(source)
                                  if item.display_text.endswith('actual file'))
                    buffer = Buffer(document=Document(source))
                    buffer.apply_completion(result)
                    self.assertEqual(shlex.split(buffer.text), ['printf', str(target)])
        result = next(item for item in self.completions('printf ~/shell')
                      if item.display_text == '~/shell directory/')
        self.assertTrue(result.text.startswith('~/'))

    def test_highlighting_preserves_unicode_multiline_text_and_syntax_classes(self):
        source = 'if true; then\n  printf "héllo $USER" | cat # 注釈\nfi'
        document = Document(source)
        line = BashLexer().lex_document(document)
        fragments = [line(number) for number in range(len(document.lines))]
        self.assertEqual('\n'.join(''.join(text for style, text in row) for row in fragments), source)
        styles = {style for row in fragments for style, text in row}
        for style in ('command', 'keyword', 'string', 'variable', 'operator', 'comment'):
            self.assertIn('class:bash.' + style, styles)
        self.assertEqual(line(100), [])

    @contextmanager
    def session(self, *, on_children=lambda: None, **settings):
        with create_pipe_input() as pipe:
            session = InteractiveSession(self.runtime, on_children, dict(self.settings, **settings),
                                         input=pipe, output=DummyOutput(),
                                         stdin=io.StringIO(), stdout=io.StringIO())
            try:
                yield session, pipe
            finally:
                session.close()

    def test_editor_completes_multiline_grammar_before_accepting(self):
        source = 'if true; then\n  printf done\nfi'
        with self.session() as (session, pipe):
            pipe.send_text(source.replace('\n', '\r') + '\r')
            self.assertEqual(session.read(), source)
            self.assertEqual(session.history.entries(), [source])
        self.assertEqual(History(self.home / 'history.json').load(), [source])

    def test_editor_history_navigation_and_tab_completion_accept_real_input(self):
        with self.session(builtin_names=['feature-command']) as (session, pipe):
            session.history.add('printf remembered')
            pipe.send_bytes(b'\x1b[A\r')
            self.assertEqual(session.read(), 'printf remembered')
            pipe.send_text('feature-com\t\r')
            self.assertEqual(session.read(), 'feature-command')

    def test_history_suggestions_follow_merged_persisted_entries(self):
        history = History(self.home / 'history.json')
        history.add('printf suggested-result')
        adapter = _EditorHistory(history)

        async def load():
            return [entry async for entry in adapter.load()]

        asyncio.run(load())
        buffer = Buffer(history=adapter)
        suggestion = AutoSuggestFromHistory().get_suggestion(buffer, Document('printf sug'))
        self.assertEqual(suggestion.text, 'gested-result')
        self.assertIsNone(AutoSuggestFromHistory().get_suggestion(buffer, Document('not present')))

    def test_child_wakeup_redraw_preserves_partial_line_and_defers_callbacks(self):
        notified = threading.Event()
        children = threading.Event()
        with self.session(on_children=children.set) as (session, pipe):
            session.notify(notified.set)
            self.assertFalse(notified.is_set())
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(session.read)
            try:
                pipe.send_text('printf partial-line')
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    editor = session.editor
                    if editor is not None and editor.default_buffer.text == 'printf partial-line':
                        break
                    time.sleep(.01)
                else:
                    self.fail('editor never received partial input')
                self.assertTrue(notified.wait(2), 'queued callback was not delivered on the prompt loop')
                children.clear()
                session.wake()
                self.assertTrue(children.wait(2), 'child wake was not delivered while editing')
                self.assertEqual(session.editor.default_buffer.text, 'printf partial-line')
                pipe.send_text('\r')
                self.assertEqual(future.result(timeout=5), 'printf partial-line')
            finally:
                pipe.close()
                executor.shutdown(wait=True)

    def test_plain_accessible_input_keeps_multiline_history_without_escapes(self):
        class TTY(io.StringIO):
            def isatty(self):
                return True

        output = TTY()
        session = InteractiveSession(self.runtime, lambda: None,
                                     dict(self.settings, accessibility=True, locale='es'),
                                     stdin=TTY('printf "first\nsecond"\n'), stdout=output)
        self.addCleanup(session.close)
        self.assertEqual(session.read(), 'printf "first\nsecond"')
        self.assertIn(i18n.translate('continuation', 'es'), output.getvalue())
        self.assertNotIn('\x1b', output.getvalue())
        self.assertFalse(session.capabilities.color)

    def test_prompt_configuration_is_literal_sanitized_and_locale_aware(self):
        self.runtime.state.last_status = 7
        with self.session(prompt='[{status}] {cwd} $(touch SHOULD-NOT-EXIST) {unknown}\x1b[31m\x07',
                          locale='es_MX.UTF-8', history_private=True) as (session, pipe):
            with patch.dict(os.environ):
                os.environ.pop('ARGUS_PROMPT', None)
                prompt = session.format_prompt()
            self.assertIn('[7] ' + str(self.home), prompt)
            self.assertIn('$(touch SHOULD-NOT-EXIST) {unknown}', prompt)
            self.assertNotIn('\x1b', prompt)
            self.assertNotIn('\x07', prompt)
            self.assertFalse((self.home / 'SHOULD-NOT-EXIST').exists())
            self.assertEqual(session._toolbar(), i18n.translate('editor.private', 'es'))
            pipe.send_text('printf unrecorded\r')
            self.assertEqual(session.read(), 'printf unrecorded')
            self.assertEqual(session.history.entries(), [])
            session.close()
            session.close()
            with self.assertRaises(RuntimeError):
                session.read()

    def test_terminal_color_and_locale_fallback(self):
        class TTY(io.StringIO):
            def isatty(self):
                return True

        with patch.dict(os.environ):
            os.environ.pop('NO_COLOR', None)
            self.assertTrue(TerminalCapabilities.detect({}, stdin=TTY(), stdout=TTY()).color)
            for settings in ({'no_color': True}, {'accessibility': True}):
                self.assertFalse(TerminalCapabilities.detect(settings, stdin=TTY(), stdout=TTY()).color)
            os.environ['NO_COLOR'] = ''
            self.assertFalse(TerminalCapabilities.detect({}, stdin=TTY(), stdout=TTY()).color)
        self.assertFalse(TerminalCapabilities.detect({}, stdin=io.StringIO(), stdout=TTY()).interactive)
        self.assertEqual(plain_text('\x01\x1b[31mhello\x1b[0m\x02\x07'), 'hello')
        self.assertEqual(i18n.normalize_locale('es-MX.UTF-8'), 'es')
        self.assertEqual(i18n.normalize_locale('not-supported'), 'en')
        self.assertEqual(i18n.translate('farewell', 'not-supported'), i18n.translate('farewell', 'en'))
        self.assertEqual(i18n.translate('missing.key', 'es'), 'missing.key')
        english, spanish = i18n._catalog('en'), i18n._catalog('es')
        self.assertEqual(english.keys(), spanish.keys())


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'history.json'

    def test_sessions_merge_new_records_without_lost_updates_or_resurrecting_deletes(self):
        first, second = History(self.path), History(self.path)
        first.load()
        second.load()
        self.assertTrue(first.add('printf first'))
        self.assertTrue(second.add('printf second'))
        self.assertEqual(first.merge(), ['printf first', 'printf second'])
        self.assertTrue(first.delete(1))
        self.assertTrue(second.add('printf third'))
        self.assertEqual(History(self.path).load(), ['printf second', 'printf third'])
        self.assertEqual(first.merge(), ['printf second', 'printf third'])

    def test_clear_invalidates_failed_pending_writes_from_older_generation(self):
        first, second = History(self.path), History(self.path)
        first.add('printf before-clear')
        second.load()
        with patch('argus.history.atomic_write', side_effect=OSError('unavailable')), \
                patch('argus.history.storage_warning'):
            self.assertFalse(second.add('printf queued-before-clear'))
        self.assertTrue(second.pending)
        self.assertTrue(first.clear())
        self.assertTrue(second.save())
        self.assertEqual(second.entries(), [])
        self.assertTrue(second.add('printf after-clear'))
        self.assertEqual(first.merge(), ['printf after-clear'])

    def test_concurrent_processes_merge_under_one_durable_lock(self):
        repository = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, PYTHONPATH=str(repository), HOME=str(self.path.parent),
                           ARGUS_CONFIG_HOME=str(self.path.parent / 'config'),
                           ARGUS_STATE_HOME=str(self.path.parent / 'state'),
                           ARGUS_DATA_HOME=str(self.path.parent / 'data'))
        source = ('import sys; from argus.history import History; '
                  'history=History(sys.argv[1]); '
                  '[history.add(sys.argv[2]+str(index)) for index in range(10)]')
        workers = [subprocess.Popen([sys.executable, '-c', source, str(self.path), f'writer-{worker}-'],
                                    cwd=repository, env=environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                   for worker in range(3)]
        try:
            for worker in workers:
                stdout, stderr = worker.communicate(timeout=15)
                self.assertEqual(worker.returncode, 0, stderr)
            self.assertEqual(set(History(self.path).load()),
                             {f'writer-{worker}-{index}' for worker in range(3) for index in range(10)})
        finally:
            for worker in workers:
                if worker.poll() is None:
                    worker.kill()
                worker.communicate()

    def test_configured_secret_patterns_are_never_saved_or_suggested(self):
        history = History(self.path)
        with patch('argus.config.get_settings', return_value={'redaction_patterns': [r'sensitive-[a-z]+']}):
            self.assertFalse(history.add('printf sensitive-account'))
            self.assertTrue(history.add('printf ordinary-output'))
            self.assertEqual(history.entries(), ['printf ordinary-output'])
        self.assertNotIn('sensitive-account', self.path.read_text())

    def test_private_ignore_secret_and_multiline_history_roundtrip(self):
        history = History(self.path, ignore=['skip *'])
        self.assertFalse(history.add('skip hidden-command'))
        self.assertFalse(history.add('export API_TOKEN=private-value'))
        self.assertFalse(history.add('printf nul\x00byte'))
        self.assertFalse(history.add('   '))
        source = 'if true; then\n  printf "line one\\nline two"\nfi'
        self.assertTrue(history.add(source))
        self.assertFalse(history.add(source), 'consecutive duplicates should not be recorded')
        history.set_private(True)
        self.assertFalse(history.add('printf private-command'))
        history.set_private(False)
        self.assertTrue(history.add('printf public-command'))
        self.assertEqual(History(self.path).load(), [source, 'printf public-command'])
        stored = self.path.read_text()
        self.assertNotIn('private-value', stored)
        self.assertNotIn('private-command', stored)
        self.assertEqual(json.loads(stored)['format'], 'argus-history-1')
        if os.name == 'posix':
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_private_fresh_session_never_creates_a_history_store(self):
        history = History(self.path, private=True)
        history.load()
        self.assertFalse(history.add('printf not-durable'))
        self.assertTrue(history.save())
        self.assertFalse(self.path.exists())

    def test_history_controls_search_delete_limit_and_private(self):
        history = History(self.path)
        for line in ('printf Alpha', 'printf beta', 'printf gamma'):
            history.add(line)
        output = io.StringIO()
        self.assertEqual(history.command(['search', 'ALPHA'], stdout=output), 0)
        self.assertIn('printf Alpha', output.getvalue())
        self.assertNotIn('printf beta', output.getvalue())
        self.assertEqual(history.command(['delete', '2']), 0)
        self.assertEqual(history.entries(), ['printf Alpha', 'printf gamma'])
        self.assertEqual(history.command(['limit', '1'], stdout=io.StringIO()), 0)
        self.assertEqual(History(self.path).load(), ['printf gamma'])
        self.assertEqual(history.command(['ignore', 'add', 'omit *']), 0)
        self.assertFalse(history.add('omit something'))
        self.assertEqual(history.command(['ignore', 'remove', 'omit *']), 0)
        self.assertTrue(history.add('omit something'))
        self.assertEqual(history.command(['private', 'on'], stdout=io.StringIO()), 0)
        self.assertFalse(history.add('printf private'))
        self.assertEqual(history.command(['clear']), 0)
        self.assertEqual(History(self.path).load(), [])
        for args in (['delete', '0'], ['delete', '999'], ['private', 'maybe'], ['limit', '0'], ['search']):
            with self.subTest(args=args):
                self.assertNotEqual(history.command(args, stdout=io.StringIO()), 0)

    def test_legacy_history_migrates_without_changing_entries(self):
        self.path.write_text('printf legacy-one\nprintf legacy-two\n')
        history = History(self.path)
        self.assertEqual(history.load(), ['printf legacy-one', 'printf legacy-two'])
        history.add('printf current')
        self.assertEqual(History(self.path).load(), ['printf legacy-one', 'printf legacy-two', 'printf current'])
        self.assertEqual(json.loads(self.path.read_text())['format'], 'argus-history-1')


if __name__ == '__main__':
    unittest.main()
