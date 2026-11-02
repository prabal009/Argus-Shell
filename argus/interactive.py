"""Native prompt-toolkit editing, Bash completion and grammar-aware continuation."""

import getpass
import os
import re
import shlex
import socket
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion, CompleteEvent, get_common_complete_suffix
from prompt_toolkit.history import History as ToolkitHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from tree_sitter import Language, Parser
import tree_sitter_bash

from . import config as configuration
from .history import History
from .i18n import set_locale, translate
from .terminal import ChildNotifications, TerminalCapabilities, plain_text

_STYLE = Style.from_dict({
    'bash.command': 'bold ansicyan', 'bash.keyword': 'bold ansimagenta',
    'bash.string': 'ansigreen', 'bash.comment': 'ansibrightblack',
    'bash.variable': 'ansiyellow', 'bash.operator': 'ansimagenta',
    'bash.number': 'ansiblue',
})
_KEYWORDS = {'if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done',
             'case', 'esac', 'in', 'function', 'select', 'time', '!'}
_OPERATORS = {'|', '||', '&', '&&', ';', ';;', '>', '>>', '<', '<<', '<<<', '>&', '<&',
              '(', ')', '{', '}', '[', ']', '[[', ']]', '=', '&>', '&>>', '|&'}


class BashLexer(Lexer):
    """Highlight grammar nodes, including nested expansions and multiline strings."""

    def __init__(self):
        self.parser = Parser(Language(tree_sitter_bash.language()))

    def lex_document(self, document):
        source = document.text.encode('utf-8', errors='surrogatepass')
        tree = self.parser.parse(source)
        spans = []

        def visit(node, inherited=''):
            kind = node.type
            style = inherited
            if kind == 'comment':
                style = 'class:bash.comment'
            elif kind in ('string', 'raw_string', 'ansi_c_string', 'heredoc_body'):
                style = 'class:bash.string'
            elif kind in ('variable_name', 'simple_expansion', 'expansion'):
                style = 'class:bash.variable'
            elif kind == 'command_name':
                style = 'class:bash.command'
            elif kind == 'number':
                style = 'class:bash.number'
            if not node.children:
                word = source[node.start_byte:node.end_byte].decode('utf-8', errors='surrogatepass')
                if not style and word in _KEYWORDS:
                    style = 'class:bash.keyword'
                elif not style and word in _OPERATORS:
                    style = 'class:bash.operator'
                spans.append((node.start_byte, node.end_byte, style))
            else:
                for child in node.children:
                    visit(child, style)

        visit(tree.root_node)
        # Tree-sitter positions are UTF-8 bytes, whereas prompt-toolkit uses
        # Unicode characters. Split byte ranges before decoding, never index
        # Python strings with tree-sitter byte offsets.
        fragments = [[]]
        cursor = 0
        for start, end, style in sorted(spans):
            if start > cursor:
                self._append(fragments, '', source[cursor:start].decode('utf-8', errors='surrogatepass'))
            if end > cursor:
                self._append(fragments, style, source[max(start, cursor):end].decode('utf-8', errors='surrogatepass'))
                cursor = end
        self._append(fragments, '', source[cursor:].decode('utf-8', errors='surrogatepass'))
        return lambda number: fragments[number] if 0 <= number < len(fragments) else []

    @staticmethod
    def _append(lines, style, text):
        pieces = text.split('\n')
        for index, piece in enumerate(pieces):
            if index:
                lines.append([])
            if piece:
                lines[-1].append((style, piece))


def _token_context(text):
    """Return the current raw word, decoded word, and command-position flag."""
    start = 0
    quote = None
    escaped = False
    command = True
    token_command = True
    in_token = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == '\\' and quote != "'":
            if not in_token:
                start, token_command, in_token = index, command, True
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            if not in_token:
                start, token_command, in_token = index, command, True
            quote = char
        elif char in ';|&\n':
            start, command, token_command, in_token = index + 1, True, True, False
        elif char in '<>':
            start, token_command, in_token = index + 1, False, False
            command = False
        elif char.isspace():
            if in_token:
                raw = text[start:index]
                if not re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', raw):
                    command = False
            start, token_command, in_token = index + 1, command, False
        elif not in_token:
            start, token_command, in_token = index, command, True
    raw = text[start:]
    try:
        pieces = shlex.split(raw + (quote or '') + ('\\' if escaped else ''), posix=True)
        word = pieces[0] if pieces else ''
    except ValueError:
        word = raw.lstrip("'\"")
    return raw, word, token_command


def _quote_path(value):
    # Preserve Bash tilde expansion instead of turning '~' into a literal path.
    if value.startswith('~/'):
        return '~/' + shlex.quote(value[2:]) if value[2:] else '~/'
    return shlex.quote(value)


class ShellCompleter(Completer):
    def __init__(self, runtime, *, builtins=(), locale='en'):
        self.runtime = runtime
        self.builtins = set(builtins)
        self.locale = locale

    def get_completions(self, document, complete_event):
        raw, word, command = _token_context(document.text_before_cursor)
        seen = set()
        state = self.runtime.state
        categories = []
        if command and '/' not in word and '\\' not in word:
            categories.extend((name, 'builtin') for name in set(getattr(self.runtime, 'builtin_names', ())) | self.builtins)
            categories.extend((name, 'function') for name in state.functions)
            categories.extend((name, 'alias') for name in state.aliases)
            path = state.variables.get('PATH', os.defpath)
            executable_suffixes = tuple(suffix.lower() for suffix in state.variables.get('PATHEXT', '.COM;.EXE;.BAT;.CMD').split(';'))
            for directory in path.split(os.pathsep):
                try:
                    with os.scandir(os.path.expanduser(directory or '.')) as entries:
                        for item in entries:
                            if not item.name.startswith(word) or not item.is_file():
                                continue
                            if os.name == 'nt':
                                if item.name.lower().endswith(executable_suffixes):
                                    categories.append((item.name, 'command'))
                            elif os.access(item.path, os.X_OK):
                                categories.append((item.name, 'command'))
                except OSError:
                    continue
        for name, category in sorted(categories):
            if name.startswith(word) and name not in seen:
                seen.add(name)
                yield Completion(shlex.quote(name), start_position=-len(raw),
                                 display=name, display_meta=translate('completion.' + category, self.locale))
        expanded = re.sub(r'\$(?:\{([A-Za-z_][A-Za-z_0-9]*)\}|([A-Za-z_][A-Za-z_0-9]*))',
                          lambda match: state.variables.get(match.group(1) or match.group(2), ''), word)
        if expanded == '~' or expanded.startswith('~/'):
            expanded = state.variables.get('HOME', os.path.expanduser('~')) + expanded[1:]
        directory, prefix = os.path.split(expanded)
        original_directory = word[:len(word) - len(os.path.basename(word))]
        if expanded != word and not word.startswith('~/'):
            # Insert a quoted resolved path: quoting "$VAR/path" as one literal
            # would otherwise silently disable the shell's variable expansion.
            original_directory = directory + os.sep if directory else ''
        try:
            with os.scandir(directory or '.') as entries:
                files = sorted(entries, key=lambda item: item.name.casefold())
            for item in files:
                if not item.name.startswith(prefix) or (item.name.startswith('.') and not prefix.startswith('.')):
                    continue
                is_directory = item.is_dir()
                candidate = original_directory + item.name + ('/' if is_directory else '')
                if candidate in seen:
                    continue
                yield Completion(_quote_path(candidate), start_position=-len(raw), display=candidate,
                                 display_meta=translate('completion.directory' if is_directory else 'completion.file', self.locale))
        except OSError:
            return


class _EditorHistory(ToolkitHistory):
    def __init__(self, history):
        super().__init__()
        self.history = history

    def load_history_strings(self):
        yield from reversed(self.history.entries())

    def store_string(self, string):
        self.history.add(string)


class InteractiveSession:
    def __init__(self, runtime, on_children, config=None, *, input=None, output=None,
                 stdin=None, stdout=None):
        self.runtime = runtime
        if config is None:
            config = configuration.get_settings()
        self.config = config
        self.stdin = sys.stdin if stdin is None else stdin
        self.stdout = sys.stdout if stdout is None else stdout
        self.input, self.output = input, output
        self.capabilities = TerminalCapabilities.detect(config, stdin=self.stdin, stdout=self.stdout)
        self.locale = set_locale(config.get('locale', 'en'))
        self.startup_files = list(config.get('startup_files', []))
        self.history = History(config.get('history_file', configuration.HISTORY_FILE),
                               config.get('history_limit', 1000),
                               private=config.get('history_private', False),
                               ignore=config.get('history_ignore', []))
        self.history.load()
        self.notifications = ChildNotifications(on_children)
        self._on_children = on_children
        self.editor = None
        self.closed = False
        self.completer = ShellCompleter(runtime, builtins=config.get('builtin_names', ()), locale=self.locale)
        self.lexer = BashLexer()

    def wake(self):
        self.notifications.wake()

    def notify(self, callback=None):
        # Calls from outside the prompt (including signal handlers) must only
        # enqueue. During editing the event loop handles the callback safely.
        if callback is not None and callback is not self._on_children:
            self.notifications.notify(callback)
        else:
            self.wake()

    def format_prompt(self, template=None):
        template = (os.environ.get('ARGUS_PROMPT') or self.config.get('prompt', 'Argus [{cwd}] > ')) if template is None else template
        state = self.runtime.state
        jobs = 0
        try:
            from . import jobs as job_control
            jobs = sum(getattr(job, 'state', '') not in ('completed', 'done') for job in job_control.jobs.values())
        except (AttributeError, ImportError):
            pass
        replacements = {'cwd': os.getcwd(), 'status': str(state.last_status), 'jobs': str(jobs),
                        'user': getpass.getuser(), 'host': socket.gethostname()}
        # Do not interpret arbitrary format specifications or expand shell code.
        prompt = re.sub(r'\{(cwd|status|jobs|user|host)\}', lambda match: replacements[match.group(1)], str(template))
        return plain_text(prompt)

    def _bindings(self):
        keys = KeyBindings()

        @keys.add('tab')
        def complete(event):
            buffer = event.current_buffer
            if buffer.complete_state:
                buffer.complete_next()
                return
            # Resolve insertion before processing a following Enter. Toolkit's
            # asynchronous default can otherwise accept the uncompleted prefix.
            completions = list(self.completer.get_completions(
                buffer.document, CompleteEvent(completion_requested=True)))
            if len(completions) == 1:
                buffer.apply_completion(completions[0])
            else:
                suffix = get_common_complete_suffix(buffer.document, completions)
                if suffix:
                    buffer.insert_text(suffix)
                elif completions:
                    buffer.start_completion()

        @keys.add('enter')
        def accept_or_continue(event):
            from .language import is_complete
            buffer = event.current_buffer
            if is_complete(buffer.text):
                buffer.validate_and_handle()
            else:
                buffer.insert_text('\n')

        @keys.add('escape', 'enter')
        def insert_newline(event):
            event.current_buffer.insert_text('\n')

        return keys

    def _toolbar(self):
        if self.history.private:
            return translate('editor.private', self.locale)
        return translate('editor.help', self.locale)

    def read(self, prompt=None):
        if self.closed:
            raise RuntimeError('interactive session is closed')
        self.history.merge()
        self._on_children()
        message = self.format_prompt(prompt)
        if self.input is None and (not self.capabilities.interactive or self.capabilities.accessible
                                   or os.environ.get('TERM') == 'dumb'):
            return self._read_plain(message)
        kwargs = {}
        if self.input is not None:
            kwargs['input'] = self.input
        if self.output is not None:
            kwargs['output'] = self.output
        self.editor = PromptSession(
            history=_EditorHistory(self.history), completer=self.completer,
            lexer=self.lexer if self.capabilities.color else None,
            auto_suggest=AutoSuggestFromHistory(), key_bindings=self._bindings(),
            multiline=True, prompt_continuation=lambda width, line, wrap: translate('continuation', self.locale),
            complete_while_typing=False, enable_history_search=True,
            style=_STYLE if self.capabilities.color else None,
            bottom_toolbar=None, reserve_space_for_menu=0, **kwargs)
        try:
            with patch_stdout(raw=False):
                return self.editor.prompt(message, pre_run=self.notifications.start)
        finally:
            self.notifications.stop()

    def _read_plain(self, prompt):
        from .language import is_complete
        lines = []
        while True:
            if self.capabilities.interactive:
                self.stdout.write(prompt if not lines else translate('continuation', self.locale))
                self.stdout.flush()
            line = self.stdin.readline()
            if not line:
                if not lines:
                    raise EOFError
                source = '\n'.join(lines)
                self.history.add(source)
                return source
            lines.append(line.rstrip('\r\n'))
            source = '\n'.join(lines)
            if is_complete(source):
                self.history.add(source)
                return source

    def close(self):
        if self.closed:
            return
        self.notifications.stop()
        self.history.save()
        self.closed = True
