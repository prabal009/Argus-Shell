"""Tree-sitter Bash syntax with an Argus-controlled, platform-independent evaluator.

Only the executor callback launches commands. In particular, no platform shell is
used to implement control flow, functions, arithmetic, or command substitution.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
import fnmatch
import io
import os
from pathlib import Path
import re
import shlex
import signal
import sys
import tempfile

from tree_sitter import Language, Parser
import tree_sitter_bash

from .expansion import Expander, ExpansionError, arithmetic


@dataclass
class Redirection:
    fd: int
    operator: str
    target: str
    expand: bool = True


@dataclass
class Command:
    argv: list[str]
    assignments: dict[str, str] = field(default_factory=dict)
    redirections: list[Redirection] = field(default_factory=list)
    source: str = ''


@dataclass
class ShellState:
    variables: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    exported: set[str] = field(default_factory=lambda: set(os.environ))
    positional: list[str] = field(default_factory=list)
    last_status: int = 0
    last_background: int | None = None
    aliases: dict[str, str] = field(default_factory=dict)
    functions: dict[str, str] = field(default_factory=dict)
    options: dict[str, bool] = field(default_factory=dict)
    traps: dict[str, str] = field(default_factory=dict)
    directory_stack: list[str] = field(default_factory=list)
    argv0: str = 'argus'
    pid: int = field(default_factory=os.getpid)
    readonly: set[str] = field(default_factory=set)
    last_command: str = ''

    def environment(self, assignments=None):
        result = {name: self.variables[name] for name in self.exported if name in self.variables}
        result.update(assignments or {})
        return result

    def snapshot(self):
        return {name: (sorted(value) if isinstance(value, set) else dict(value) if isinstance(value, dict) else list(value) if isinstance(value, list) else value) for name, value in vars(self).items()}

    @classmethod
    def from_snapshot(cls, data):
        values = {name: value for name, value in data.items() if name in cls.__dataclass_fields__}
        for name in ('exported', 'readonly'):
            if name in values: values[name] = set(values[name])
        return cls(**values)


class LanguageError(ValueError):
    pass


class _Flow(Exception):
    def __init__(self, kind, value=0):
        self.kind, self.value = kind, value


def _parser():
    return Parser(Language(tree_sitter_bash.language()))


def _heredoc_header_span(node, *, recovery=False):
    if node.type != 'heredoc_redirect':
        return None
    delimiter = next((c for c in node.named_children if c.type == 'heredoc_start'), None)
    if delimiter is None:
        return None
    operator = node.child_by_field_name('operator')
    separators = [c for c in node.named_children if c.type == 'pipeline']
    if operator is not None:
        separators.append(operator)
    if recovery:
        separators.extend(c for c in node.children if c.is_error and re.match(rb'(?:\|\||&&|\|&|\|)', c.text))
    if not separators:
        return None
    return delimiter.end_byte, min(c.start_byte for c in separators)


def _grammar_source(source):
    # Equal-byte-width syntax normalization works around grammar restrictions;
    # expansion, diagnostics and source storage always read the original bytes.
    normalized = source.replace('<>', '>|').replace('<<<', '>  ')
    if '<<' not in normalized:
        return normalized
    data = normalized.encode()
    original = source.encode()
    rewritten = bytearray(data)
    tree = _parser().parse(data)
    def visit(node):
        span = _heredoc_header_span(node, recovery=True)
        if span is not None:
            start, end = span
            header = original[start:end]
            if header.strip() and b'\n' not in header:
                # The grammar accepts heredoc arguments OR a pipeline, not
                # their valid combination. Validate arguments independently,
                # then hide them only in the syntax view and recover below.
                candidate = b': ' + header.replace(b'<>', b'>|').replace(b'<<<', b'>  ')
                if not _parser().parse(candidate).root_node.has_error:
                    rewritten[start:end] = b' ' * (end - start)
        for child in node.named_children:
            visit(child)
    visit(tree.root_node)
    return rewritten.decode()


def parse(source, filename='<input>'):
    if '\x00' in source: raise LanguageError(f'{filename}:1: NUL is not allowed in shell input')
    tree = _parser().parse(_grammar_source(source).encode())
    if tree.root_node.has_error:
        def bad(node):
            for child in node.children:
                if child.is_error or child.is_missing: return child
                if child.has_error: return bad(child)
            return node
        node = bad(tree.root_node)
        raise LanguageError(f'{filename}:{node.start_point.row + 1}: invalid or incomplete syntax near {source.encode()[node.start_byte:node.end_byte].decode(errors="replace")!r}')
    # Explicitly reject grammar features not evaluated rather than silently
    # interpreting their source as ordinary argv text.
    def supported(node):
        if node.type in {'process_substitution', 'array', 'subscript', 'translated_string', 'ansi_c_string'}:
            raise LanguageError(f'{filename}:{node.start_point.row + 1}: unsupported syntax: {node.type}')
        if node.type == 'for_statement' and source.encode()[node.start_byte:node.start_byte + 6] == b'select':
            raise LanguageError(f'{filename}:{node.start_point.row + 1}: select is not supported')
        if node.type == 'extglob_pattern' and re.search(rb'[@!?*+]\(', source.encode()[node.start_byte:node.end_byte]):
            raise LanguageError(f'{filename}:{node.start_point.row + 1}: unsupported syntax: extended glob pattern')
        span = _heredoc_header_span(node)
        if span is not None:
            header = source.encode()[span[0]:span[1]].decode()
            if header.strip():
                parse(': ' + header, filename)
        for child in node.named_children: supported(child)
    supported(tree.root_node)
    return tree


def is_complete(source):
    """False only for input that can usefully be continued at an interactive prompt."""
    if not source.strip(): return True
    tree = _parser().parse(_grammar_source(source).encode())
    if not tree.root_node.has_error:
        named = tree.root_node.named_children
        if named and named[-1].type == 'comment': return True
        trailing = len(source) - len(source.rstrip('\\'))
        return trailing % 2 == 0
    quote, escaped, stack = None, False, []
    for ch in source:
        if escaped: escaped = False; continue
        if ch == '\\' and quote != "'": escaped = True; continue
        if quote:
            if ch == quote: quote = None
            continue
        if ch in "'\"`": quote = ch
        elif ch in '({': stack.append(ch)
        elif ch in ')}' and stack: stack.pop()
    if quote or escaped or stack: return False
    if re.search(r'(?:\|\||&&|\|)\s*$', source): return False
    # Keywords in strings/comments do not open compounds; inspect parser tokens.
    tokens = []
    def visit(node):
        if not node.children and not node.is_named and not node.is_missing: tokens.append(node.type)
        for child in node.children: visit(child)
    visit(tree.root_node)
    for opening, closing in (('if', 'fi'), ('do', 'done'), ('case', 'esac')):
        if tokens.count(opening) > tokens.count(closing): return False
    if re.search(r'\b(?:for|while|until)\b', source) and not re.search(r'\bdone\b', source): return False
    heredocs = re.findall(r'<<-?\s*([\'\"]?)([^\s;<>]+)\1', source)
    for _, delimiter in heredocs:
        delimiter = delimiter.strip("'\"")
        if not any(line.lstrip('\t') == delimiter for line in source.splitlines()[1:]): return False
    return True


def command_text(command):
    if isinstance(command, (list, tuple)): return ' | '.join(command_text(item) for item in command)
    chunks = [name + '=' + shlex.quote(value) for name, value in command.assignments.items()]
    chunks += [shlex.join(command.argv)] if command.argv else []
    for redir in command.redirections:
        chunks.append(f'{redir.fd}{redir.operator} ' + shlex.quote(redir.target))
    return ' '.join(chunks)


class ShellRuntime:
    builtin_names = {'export', 'unset', 'unsetenv', 'source', '.', 'read', 'umask', 'exec', 'set', 'shift', 'trap', 'type', 'command', 'alias', 'unalias', 'pushd', 'popd', 'dirs', 'return', 'break', 'continue', 'eval', 'true', 'false', ':', 'local', 'declare', 'typeset', 'readonly', '__argus_eval__', '__argus_test__', '__argus_arithmetic__'}
    builtin_names |= {'__argus_define__', '__argus_assign__', '__argus_subshell__'}

    def __init__(self, executor, state=None, stdin=None, stdout=None, stderr=None):
        self.executor = executor
        self.state = state if state is not None else ShellState()
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self.bypass_functions = False
        self.exec_requested = False
        self.execute_external = None
        self.classify_command = None
        self._signals = deque()
        self._draining = False
        self._contexts = []
        self._function_frames = []
        self._loop_depth = 0
        self._source_depth = 0
        self._alias_stack = set()

    def has_function(self, name):
        return not self.bypass_functions and name in self.state.functions

    @contextmanager
    def assignment_scope(self, assignments):
        if not assignments:
            yield
            return
        for key in assignments:
            if key in self.state.readonly:
                raise ExpansionError(f'{key}: readonly variable')
        previous = {key: self.state.variables.get(key) for key in assignments}
        exported = set(self.state.exported)
        self.state.variables.update(assignments)
        self.state.exported.update(assignments)
        try: yield
        finally:
            for key, value in previous.items():
                if value is None: self.state.variables.pop(key, None)
                else: self.state.variables[key] = value
                if key in exported: self.state.exported.add(key)
                else: self.state.exported.discard(key)

    def _text(self, node):
        return self._contexts[-1][0][node.start_byte:node.end_byte].decode()

    def _error(self, node, message):
        return LanguageError(f'{self._contexts[-1][1]}:{node.start_point.row + 1}: {message}')

    def run(self, source, *, filename='<input>'):
        try:
            tree = parse(source, filename)
            if self.state.options.get('noexec'):
                self.state.last_status = 0
                return 0
            self._contexts.append((source.encode(), filename))
            try: status = self._sequence(tree.root_node.children)
            finally: self._contexts.pop()
        except _Flow as flow:
            if self._contexts or self._source_depth or self._function_frames: raise
            if flow.kind == 'errexit':
                status = flow.value
            else:
                print(f'{filename}: {flow.kind}: not in a function or loop', file=self.stderr)
                status = 2
        except (LanguageError, ExpansionError, OSError) as error:
            message = str(error)
            if not message.startswith(filename + ':'): message = filename + ': ' + message
            print(message, file=self.stderr)
            status = 2 if isinstance(error, (LanguageError, ExpansionError)) else 1
        self.state.last_status = int(status)
        return int(status)

    def _sequence(self, children):
        children = list(children)
        status = 0
        for index, child in enumerate(children):
            if not child.is_named or child.type in ('comment', 'heredoc_body', 'heredoc_end'): continue
            if self.state.options.get('noexec'): break
            self.drain_traps()
            background = index + 1 < len(children) and children[index + 1].type == '&'
            status = self._eval(child, background=background)
            self.state.last_status = status
        return status

    def _dispatch(self, commands, background=False):
        if self.state.options.get('noexec'):
            return 0
        for command in commands:
            for name in command.assignments:
                if name in self.state.readonly:
                    raise ExpansionError(f'{name}: readonly variable')
        if self.state.options.get('xtrace'):
            print('+ ' + command_text(commands), file=self.stderr)
        substitution_status = getattr(self, '_substitution_status', None)
        self._substitution_status = None
        self._run_trap('DEBUG')
        status = int(self.executor(commands, background, self))
        if not background and len(commands) == 1 and not commands[0].argv and status == 0:
            for name, value in commands[0].assignments.items(): self._assign(name, value)
            if substitution_status is not None:
                status = substitution_status
        self.state.last_status = status
        if status and not getattr(self, '_condition_depth', 0):
            self._run_trap('ERR')
            if self.state.options.get('errexit'):
                raise _Flow('errexit', status)
        return status

    def assign_parameter(self, name, value):
        previous = getattr(self, '_substitution_status', None)
        try:
            status = self._dispatch([Command(['__argus_assign__', name, value], source=name + '=' + shlex.quote(value))])
        finally:
            self._substitution_status = previous
        if status:
            raise ExpansionError(f'{name}: assignment refused (status {status})')

    def evaluate_arithmetic(self, expression):
        self._arithmetic_result = None
        previous = getattr(self, '_substitution_status', None)
        try:
            with self._condition():
                status = self._dispatch([Command(['__argus_arithmetic__', expression], source='((' + expression + '))')])
        finally:
            self._substitution_status = previous
        if self._arithmetic_result is None or status not in (0, 1):
            raise ExpansionError(f'arithmetic evaluation refused (status {status})')
        return self._arithmetic_result

    def _validate_prefix_assignments(self, node):
        if node.type == 'variable_assignment':
            name = self._text(node.child_by_field_name('name'))
            if name in self.state.readonly:
                raise ExpansionError(f'{name}: readonly variable')
        elif node.type == 'redirected_statement':
            body = node.child_by_field_name('body')
            if body is not None:
                self._validate_prefix_assignments(body)
        elif node.type in ('command', 'variable_assignments', 'pipeline'):
            for child in node.named_children:
                self._validate_prefix_assignments(child)

    def _assign(self, name, value):
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            raise ExpansionError('invalid variable name: ' + name)
        if name in self.state.readonly: raise ExpansionError(f'{name}: readonly variable')
        self.state.variables[name] = value
        if self.state.options.get('allexport') or self.state.options.get('a'): self.state.exported.add(name)

    def _command(self, node, expander=None):
        expand = expander or Expander(self)
        if not expand.preview:
            self._validate_prefix_assignments(node)
        self._substitution_status = None
        alias_node = node.child_by_field_name('body') if node.type == 'redirected_statement' else node
        if not expand.preview and alias_node is not None and alias_node.type == 'command':
            name_node = alias_node.child_by_field_name('name')
            name = self._text(name_node) if name_node is not None else ''
            if name in self.state.aliases and name not in self._alias_stack:
                # Pipeline stages expand aliases in their isolated interpreter.
                return Command(['__argus_eval__', self._text(node)], source=self._text(node))
        if node.type == 'redirected_statement':
            body = node.child_by_field_name('body')
            command = self._command(body, expand) if body else Command([], {}, [], self._text(node))
            for child in node.named_children:
                if child.type.endswith('_redirect'):
                    span = _heredoc_header_span(child)
                    if span is not None:
                        raw_header = self._contexts[-1][0][span[0]:span[1]].decode()
                        if raw_header.strip():
                            header_source = ': ' + raw_header
                            header_tree = parse(header_source, self._contexts[-1][1])
                            self._contexts.append((header_source.encode(), self._contexts[-1][1]))
                            try:
                                extra = self._command(header_tree.root_node.named_children[0], expand)
                            finally:
                                self._contexts.pop()
                            command.argv.extend(extra.argv[1:])
                            for redirection in extra.redirections:
                                redirection._position += span[0] - 2
                            command.redirections.extend(extra.redirections)
                    else:
                        for argument in child.children_by_field_name('argument'):
                            command.argv.extend(expand.word(self._text(argument)))
                    command.redirections.extend(self._redirections(child, expand))
            command.redirections.sort(key=lambda r: getattr(r, '_position', 0))
            command.source = self._text(node)
            return command
        if node.type not in {'command', 'variable_assignment', 'variable_assignments', 'declaration_command', 'unset_command'}:
            if node.type == 'subshell': return Command(['__argus_subshell__', self._text(node)[1:-1]], source=self._text(node))
            if node.type == 'test_command': return Command(['__argus_test__', self._text(node)], source=self._text(node))
            if node.type == 'compound_statement' and self._text(node).startswith('(('): return Command(['__argus_arithmetic__', self._text(node)[2:-2]], source=self._text(node))
            return Command(['__argus_eval__', self._text(node)], source=self._text(node))
        argv, assignments, redirections = [], {}, []
        if node.type in ('declaration_command', 'unset_command'):
            argv.append(self._text(node.children[0]))
        parts = [node] if node.type == 'variable_assignment' else node.named_children
        for child in parts:
            if child.type == 'comment': continue
            if child.type.endswith('_redirect'):
                redirections.extend(self._redirections(child, expand)); continue
            if child.type == 'variable_assignment':
                name_node = child.child_by_field_name('name')
                name = self._text(name_node)
                value_node = child.child_by_field_name('value')
                with self.assignment_scope(assignments):
                    value = expand.scalar(self._text(value_node)) if value_node else ''
                if '+=' in self._text(child)[:self._text(child).find('=') + 1]: value = self.state.variables.get(name, '') + value
                if node.type == 'declaration_command': argv.append(name + '=' + value)
                else: assignments[name] = value
            else:
                argv.extend(expand.word(self._text(child), split=node.type != 'declaration_command', globbing=node.type != 'declaration_command' and not self.state.options.get('noglob')))
        return Command(argv, assignments, redirections, self._text(node))

    def _redirections(self, node, expand):
        text = self._text(node)
        match = re.match(r'(\d*)\s*(<<<|<<-|<<|&>>|&>|>>|<>|>\||<&-|>&-|<&|>&|<|>)', text)
        if not match: raise self._error(node, 'unsupported redirection')
        descriptor, operator = match.groups()
        fd = int(descriptor) if descriptor else (0 if operator.startswith('<') else 1)
        do_expand = True
        if operator in ('<<', '<<-'):
            start = next((c for c in node.named_children if c.type == 'heredoc_start'), None)
            body = next((c for c in node.named_children if c.type == 'heredoc_body'), None)
            delimiter = self._text(start) if start else ''
            do_expand = not any(c in delimiter for c in "'\"\\")
            target = self._text(body) if body else ''
            # Grammar body begins immediately after the opening newline.
            if operator == '<<-': target = ''.join(line.lstrip('\t') for line in target.splitlines(keepends=True))
            if do_expand: target = expand.scalar(target, heredoc=True)
        elif operator in ('<&-', '>&-'):
            operator, target = operator[:-1], '-'
        else:
            destination = [c for c in node.named_children if c.type != 'file_descriptor']
            raw = ' '.join(self._text(c) for c in destination)
            values = expand.word(raw, split=operator != '<<<', globbing=operator != '<<<', braces=False)
            if len(values) != 1: raise self._error(node, 'ambiguous redirection')
            target = values[0]
        redirection = Redirection(fd, operator, target, do_expand)
        redirection._position = node.start_byte
        return [redirection]

    @contextmanager
    def _condition(self):
        self._condition_depth = getattr(self, '_condition_depth', 0) + 1
        try: yield
        finally: self._condition_depth -= 1

    def _eval(self, node, background=False):
        previous = getattr(self, '_location', None)
        self._location = (self._contexts[-1][1], node.start_point.row + 1)
        try:
            return self._evaluate(node, background=background)
        except ExpansionError as error:
            raise self._error(node, str(error)) from error
        finally:
            self._location = previous

    def _evaluate(self, node, background=False):
        kind = node.type
        self._validate_prefix_assignments(node)
        alias_node = node.child_by_field_name('body') if kind == 'redirected_statement' else node
        if alias_node is not None and alias_node.type == 'command':
            name_node = alias_node.child_by_field_name('name')
            name = self._text(name_node) if name_node is not None else ''
            if name in self.state.aliases and name not in self._alias_stack:
                raw = self._text(node).encode()
                start, end = name_node.start_byte - node.start_byte, name_node.end_byte - node.start_byte
                replacement = (raw[:start] + self.state.aliases[name].encode() + raw[end:]).decode()
                self._alias_stack.add(name)
                try: return self.run(replacement + (' &' if background else ''), filename=self._contexts[-1][1])
                finally: self._alias_stack.remove(name)
        if kind == 'redirected_statement':
            heredocs = [c for c in node.named_children if c.type == 'heredoc_redirect']
            pipelines = [c for h in heredocs for c in h.named_children if c.type == 'pipeline']
            if pipelines:
                commands = [self._command(node)]
                for pipeline in pipelines:
                    commands.extend(self._command(c) for c in pipeline.named_children)
                return self._dispatch(commands, background)
            for heredoc in heredocs:
                right = heredoc.child_by_field_name('right')
                operator = heredoc.child_by_field_name('operator')
                if right is not None and operator is not None:
                    with self._condition(): status = self._dispatch([self._command(node)], background)
                    op = self._text(operator)
                    if (op == '&&' and status == 0) or (op == '||' and status != 0):
                        return self._eval(right)
                    return status
        if background and kind != 'pipeline': return self._dispatch([self._command(node)], True)
        if kind in {'command', 'redirected_statement', 'variable_assignment', 'variable_assignments', 'declaration_command', 'unset_command', 'test_command'}:
            return self._dispatch([self._command(node)])
        if kind in ('program', 'do_group', 'else_clause'): return self._sequence(node.children)
        if kind == 'compound_statement':
            if self._text(node).startswith('(('): return self._dispatch([self._command(node)])
            return self._sequence(node.children)
        if kind == 'subshell':
            source = self._text(node)[1:-1]
            return self._dispatch([Command(['__argus_subshell__', source], source=self._text(node))])
        if kind == 'pipeline':
            commands = [self._command(c) for c in node.named_children if c.type != 'comment']
            separators = [c.type for c in node.children if not c.is_named]
            for index, separator in enumerate(separators):
                if separator == '|&' and index < len(commands) - 1: commands[index].redirections.append(Redirection(2, '>&', '1'))
            return self._dispatch(commands, background)
        if kind == 'list':
            left, right = [c for c in node.named_children if c.type != 'comment']
            op = next(c.type for c in node.children if c.type in ('&&', '||'))
            with self._condition(): status = self._eval(left)
            if (op == '&&' and status == 0) or (op == '||' and status != 0): return self._eval(right)
            return status
        if kind == 'negated_command':
            with self._condition(): return int(self._eval(node.named_children[0]) == 0)
        if kind == 'if_statement':
            children = list(node.children)
            then = next(i for i,c in enumerate(children) if c.type == 'then')
            with self._condition(): condition = self._sequence(children[1:then])
            clauses = [c for c in children[then + 1:] if c.type in ('elif_clause', 'else_clause')]
            body = children[then + 1:]
            if clauses: body = body[:body.index(clauses[0])]
            if condition == 0: return self._sequence(body)
            for clause in clauses:
                if clause.type == 'else_clause': return self._sequence(clause.children)
                parts = list(clause.children)
                then = next(i for i,c in enumerate(parts) if c.type == 'then')
                with self._condition(): condition = self._sequence(parts[1:then])
                if condition == 0: return self._sequence(parts[then + 1:])
            return 0
        if kind in ('for_statement', 'while_statement', 'c_style_for_statement'):
            return self._loop(node)
        if kind == 'case_statement':
            value = Expander(self).scalar(self._text(node.child_by_field_name('value')))
            status, fallthrough = 0, False
            for item in (c for c in node.named_children if c.type == 'case_item'):
                patterns = item.children_by_field_name('value')
                if fallthrough or any(fnmatch.fnmatchcase(value, Expander(self).pattern(self._text(p))) for p in patterns):
                    closing = next(i for i,c in enumerate(item.children) if c.type == ')')
                    status = self._sequence(item.children[closing + 1:])
                    ending = item.children[-1].type
                    if ending == ';&': fallthrough = True; continue
                    if ending == ';;&': fallthrough = False; continue
                    break
            return status
        if kind == 'function_definition':
            return self._dispatch([Command(['__argus_define__', self._text(node)], source=self._text(node))])
        raise self._error(node, 'unsupported syntax: ' + kind)

    def _loop(self, node):
        body = node.child_by_field_name('body')
        status = 0
        self._loop_depth += 1
        try:
            if node.type == 'for_statement':
                name = self._text(node.child_by_field_name('variable'))
                value_nodes = node.children_by_field_name('value')
                values = [v for n in value_nodes for v in Expander(self).word(self._text(n))] if value_nodes else list(self.state.positional)
                iterator = iter(values)
            elif node.type == 'c_style_for_statement':
                for expr in node.children_by_field_name('initializer'): self.evaluate_arithmetic(self._text(expr))
            while True:
                if self.state.options.get('noexec'): break
                if node.type == 'for_statement':
                    try: value = next(iterator)
                    except StopIteration: break
                    status = self._dispatch([Command(['__argus_assign__', name, value], source=name + '=' + shlex.quote(value))])
                    if status: return status
                elif node.type == 'while_statement':
                    conditions = node.children_by_field_name('condition')
                    with self._condition(): result = self._sequence(conditions)
                    until = self._text(node).lstrip().startswith('until')
                    if (result == 0) == until: break
                else:
                    conditions = node.children_by_field_name('condition')
                    if conditions:
                        result = 0
                        for condition in conditions:
                            result = self.evaluate_arithmetic(self._text(condition))
                        if not result: break
                try: status = self._eval(body)
                except _Flow as flow:
                    if flow.kind not in ('break', 'continue'): raise
                    if flow.value > 1: raise _Flow(flow.kind, flow.value - 1)
                    if flow.kind == 'break': break
                if node.type == 'c_style_for_statement':
                    for expr in node.children_by_field_name('update'): self.evaluate_arithmetic(self._text(expr))
            return status
        finally: self._loop_depth -= 1

    @contextmanager
    def _isolated(self):
        previous, cwd = self.state, os.getcwd()
        environment = dict(os.environ)
        self.state = ShellState.from_snapshot(previous.snapshot())
        mask = os.umask(0); os.umask(mask)
        try: yield
        finally:
            self.state = previous
            os.chdir(cwd)
            os.environ.clear()
            os.environ.update(environment)
            os.umask(mask)

    def capture(self, source):
        # Temporary file avoids pipe-buffer deadlocks for large substitutions.
        with self._isolated(), tempfile.TemporaryFile(mode='w+b') as capture:
            old_stdout = self.stdout
            saved_fd = None
            try:
                try: sys.stdout.flush(); saved_fd = os.dup(1); os.dup2(capture.fileno(), 1)
                except OSError: pass
                stream = io.TextIOWrapper(os.fdopen(os.dup(capture.fileno()), 'wb', closefd=True), encoding='utf-8', write_through=True)
                self.stdout = stream
                try:
                    status = self._dispatch([Command(['__argus_subshell__', source], source=source)])
                except _Flow as flow:
                    if flow.kind not in ('errexit', 'return'): raise
                    status = flow.value
                self._substitution_status = status
                stream.flush()
                capture.seek(0)
                return capture.read().decode('utf-8', errors='replace')
            finally:
                self.stdout = old_stdout
                if 'stream' in locals(): stream.close()
                if saved_fd is not None: os.dup2(saved_fd, 1); os.close(saved_fd)

    def deliver_signal(self, signum):
        self._signals.append(signum)

    def _run_trap(self, name):
        body = self.state.traps.get(name)
        if not body or getattr(self, '_trap_depth', 0):
            return
        status = self.state.last_status
        self._trap_depth = getattr(self, '_trap_depth', 0) + 1
        try:
            self.run(body, filename=f'<trap {name}>')
        finally:
            self._trap_depth -= 1
            self.state.last_status = status

    def drain_traps(self):
        if self._draining: return
        self._draining = True
        try:
            while self._signals:
                signum = self._signals.popleft()
                try: name = signal.Signals(signum).name.removeprefix('SIG')
                except ValueError: name = str(signum)
                key = name if name in self.state.traps else str(signum)
                self._run_trap(key)
        finally: self._draining = False

    def _function(self, name, args):
        source = self.state.functions[name]
        tree = parse(source, f'<function {name}>')
        definition = tree.root_node.named_children[0]
        body = definition.child_by_field_name('body')
        previous = self.state.positional
        self.state.positional = list(args)
        frame = {}
        self._function_frames.append(frame)
        self._contexts.append((source.encode(), f'<function {name}>'))
        try:
            try:
                redirects = definition.children_by_field_name('redirect')
                if redirects:
                    command = self._command(body)
                    for redirect in redirects:
                        command.redirections.extend(self._redirections(redirect, Expander(self)))
                    status = self._dispatch([command])
                else:
                    status = self._eval(body)
            except _Flow as flow:
                if flow.kind != 'return': raise
                status = flow.value
            self.state.last_status = status
            self._run_trap('RETURN')
            return status
        finally:
            self._contexts.pop()
            self._function_frames.pop()
            self.state.positional = previous
            for key, (existed, value, exported, readonly) in frame.items():
                if existed: self.state.variables[key] = value
                else: self.state.variables.pop(key, None)
                if exported: self.state.exported.add(key)
                else: self.state.exported.discard(key)
                if readonly: self.state.readonly.add(key)
                else: self.state.readonly.discard(key)

    def _print(self, *values): print(*values, file=self.stdout)

    def run_builtin(self, argv):
        if not argv: return 0
        name, args = argv[0], argv[1:]
        if self.has_function(name): return self._function(name, args)
        if name not in self.builtin_names: return None
        try: return self._builtin(name, args)
        except (ValueError, OSError) as error:
            location = getattr(self, '_location', None)
            prefix = f'{location[0]}:{location[1]}: ' if location else ''
            print(f'{prefix}{name}: {error}', file=self.stderr)
            return 1

    def _builtin(self, name, args):
        s = self.state
        if name in ('true', ':'): return 0
        if name == 'false': return 1
        if name == '__argus_eval__': return self.run(args[0], filename='<compound>')
        if name == '__argus_subshell__':
            with nullcontext() if getattr(self, 'isolated_worker', False) else self._isolated():
                try:
                    return self.run(args[0], filename='<subshell>')
                except _Flow as flow:
                    if flow.kind in ('errexit', 'return'): return flow.value
                    raise
        if name == '__argus_arithmetic__':
            self._arithmetic_result = arithmetic(args[0], s)
            return int(self._arithmetic_result == 0)
        if name == '__argus_assign__':
            self._assign(args[0], args[1])
            return 0
        if name == '__argus_define__':
            definition = parse(args[0], '<function definition>').root_node.named_children[0]
            if definition.type != 'function_definition': raise ValueError('expected function definition')
            key = args[0].encode()[definition.child_by_field_name('name').start_byte:definition.child_by_field_name('name').end_byte].decode()
            s.functions[key] = args[0]
            return 0
        if name == '__argus_test__': return self._test(args[0])
        if name in ('return', 'break', 'continue'):
            if len(args) > 1: raise ValueError('too many arguments')
            value = int(args[0]) if args else (s.last_status if name == 'return' else 1)
            if name != 'return' and (value < 1 or not self._loop_depth): raise ValueError('not in a loop or invalid loop count')
            if name == 'return' and not (self._function_frames or self._source_depth): raise ValueError('not in a function or sourced script')
            raise _Flow(name, value % 256 if name == 'return' else value)
        if name in ('source', '.'):
            if not args: raise ValueError('filename required')
            path = Path(args[0])
            if not path.is_absolute() and not any(sep in args[0] for sep in ('/', '\\')):
                path = next((Path(p) / args[0] for p in s.variables.get('PATH', '').split(os.pathsep) if (Path(p) / args[0]).is_file()), path)
            source = path.read_text(encoding='utf-8')
            previous = s.positional
            if len(args) > 1: s.positional = args[1:]
            self._source_depth += 1
            try:
                try: status = self.run(source, filename=str(path))
                except _Flow as flow:
                    if flow.kind != 'return': raise
                    status = flow.value
                self.state.last_status = status
                self._run_trap('RETURN')
                return status
            finally:
                self._source_depth -= 1
                if len(args) > 1: s.positional = previous
        if name == 'eval': return self.run(' '.join(args), filename='<eval>')
        if name in ('export', 'local', 'declare', 'typeset', 'readonly'):
            unexport = False
            flags = set()
            while args and args[0].startswith('-') and args[0] != '-':
                option, args = args[0], args[1:]
                if option == '--': break
                if option == '-n' and name == 'export': unexport = True; continue
                flags.update(option[1:])
                if any(c not in 'pxrf' for c in option[1:]): raise ValueError('unsupported option: ' + option)
            if 'f' in flags:
                if name != 'declare' and name != 'typeset': raise ValueError('function export is not supported')
                for function in args or sorted(s.functions):
                    if function not in s.functions: return 1
                    self._print(s.functions[function])
                return 0
            if not args:
                names = s.exported if name == 'export' else s.readonly if name == 'readonly' else s.variables
                for key in sorted(names):
                    if key in s.variables: self._print(('export ' if name == 'export' else '') + key + '=' + shlex.quote(s.variables[key]))
                return 0
            for item in args:
                key, equal, value = item.partition('=')
                if not re.fullmatch(r'[A-Za-z_]\w*', key): raise ValueError('invalid identifier: ' + key)
                if name == 'local':
                    if not self._function_frames: raise ValueError('not in a function')
                    self._function_frames[-1].setdefault(key, (key in s.variables, s.variables.get(key), key in s.exported, key in s.readonly))
                if equal: self._assign(key, value)
                elif key not in s.variables: self._assign(key, '')
                if name == 'export' or 'x' in flags:
                    if unexport: s.exported.discard(key)
                    else: s.exported.add(key)
                if name == 'readonly' or 'r' in flags: s.readonly.add(key)
            return 0
        if name in ('unset', 'unsetenv'):
            functions = bool(args and args[0] == '-f')
            if args and args[0] in ('-f', '-v'): args = args[1:]
            for key in args:
                if functions: s.functions.pop(key, None)
                else:
                    if key in s.readonly: raise ValueError(key + ': readonly variable')
                    s.variables.pop(key, None); s.exported.discard(key)
            return 0
        if name == 'shift':
            if len(args) > 1: raise ValueError('too many arguments')
            count = int(args[0]) if args else 1
            if count < 0 or count > len(s.positional): return 1
            del s.positional[:count]; return 0
        if name == 'set':
            if not args:
                for key in sorted(s.variables): self._print(key + '=' + shlex.quote(s.variables[key]))
                return 0
            known = {'a': 'allexport', 'e': 'errexit', 'f': 'noglob', 'u': 'nounset', 'x': 'xtrace', 'n': 'noexec', 'C': 'noclobber'}
            while args and args[0][:1] in ('-', '+'):
                option, args = args[0], args[1:]
                if option == '--': s.positional = args; return 0
                enable = option[0] == '-'
                if option in ('-o', '+o'):
                    if not args:
                        for key in sorted(set(known.values()) | {'pipefail'}): self._print(key, 'on' if s.options.get(key) else 'off')
                        return 0
                    key, args = args[0], args[1:]
                    if key not in set(known.values()) | {'pipefail'}: raise ValueError('unknown option: ' + key)
                    s.options[key] = enable
                else:
                    for flag in option[1:]:
                        if flag not in known: raise ValueError('unknown option: ' + flag)
                        s.options[known[flag]] = enable
                if not option[1:]: break
            if args: s.positional = args
            return 0
        if name == 'read': return self._read(args)
        if name == 'umask':
            if not args:
                mask = os.umask(0); os.umask(mask); self._print(f'{mask:04o}'); return 0
            if len(args) != 1: raise ValueError('expected one mask')
            if re.fullmatch('[0-7]{1,4}', args[0]): os.umask(int(args[0], 8)); return 0
            mask = os.umask(0); os.umask(mask)
            permissions = 0o777 & ~mask
            for clause in args[0].split(','):
                match = re.fullmatch(r'([ugoa]*)([=+-])([rwx]*)', clause)
                if not match: raise ValueError('invalid symbolic mask')
                who, op, modes = match.groups(); who = who or 'a'
                selected = 0
                bits = sum({'r': 4, 'w': 2, 'x': 1}[c] for c in set(modes))
                for c, shift in (('u', 6), ('g', 3), ('o', 0)):
                    if c in who or 'a' in who:
                        selected |= 7 << shift
                        if op == '=': permissions = (permissions & ~(7 << shift)) | (bits << shift)
                        elif op == '+': permissions |= bits << shift
                        else: permissions &= ~(bits << shift)
            os.umask(0o777 & ~permissions); return 0
        if name == 'trap':
            if not args or args == ['-p']:
                for key, body in sorted(s.traps.items()): self._print('trap -- ' + shlex.quote(body) + ' ' + key)
                return 0
            if args == ['-l']:
                self._print(' '.join(f'{sig.value}) {sig.name}' for sig in signal.Signals)); return 0
            if args[0] == '--': args = args[1:]
            if len(args) < 2: raise ValueError('action and signal required')
            body = args[0]
            for key in args[1:]:
                key = key.upper().removeprefix('SIG')
                if key == '0': key = 'EXIT'
                if key.isdigit(): key = signal.Signals(int(key)).name.removeprefix('SIG')
                if key not in ('EXIT', 'ERR', 'DEBUG', 'RETURN') and not hasattr(signal, 'SIG' + key): raise ValueError('invalid signal: ' + key)
                if body == '-': s.traps.pop(key, None)
                else: s.traps[key] = body
            return 0
        if name in ('alias', 'unalias'):
            if name == 'unalias':
                if args == ['-a']: s.aliases.clear(); return 0
                status = 0
                for key in args:
                    if key not in s.aliases: status = 1
                    s.aliases.pop(key, None)
                return status
            if not args:
                for key, value in sorted(s.aliases.items()): self._print('alias ' + key + '=' + shlex.quote(value))
                return 0
            status = 0
            for arg in args:
                key, equal, value = arg.partition('=')
                if equal:
                    if not re.fullmatch(r'[A-Za-z_][\w.-]*', key): raise ValueError('invalid alias name')
                    s.aliases[key] = value
                elif key in s.aliases: self._print('alias ' + key + '=' + shlex.quote(s.aliases[key]))
                else: status = 1
            return status
        if name in ('pushd', 'popd', 'dirs'): return self._directories(name, args)
        if name in ('type', 'command', 'exec'):
            if name == 'type' or name == 'command' and args and args[0] in ('-v', '-V'):
                verbose = name == 'type' or args[0] == '-V'
                if name == 'command': args = args[1:]
                status = 0
                import shutil
                for item in args:
                    if item in s.aliases: description, value = 'alias', s.aliases[item]
                    elif self.has_function(item): description, value = 'function', item
                    elif item in self.builtin_names: description, value = 'shell builtin', item
                    elif self.classify_command and self.classify_command(item): description, value = 'shell builtin', item
                    else:
                        value = shutil.which(item, path=s.variables.get('PATH', ''))
                        description = 'file'
                    if value: self._print(f'{item} is {description} {value}' if verbose else value)
                    else: status = 1
                return status
            if args and args[0] == '--': args = args[1:]
            if not args: return 0
            old_bypass, old_exec = self.bypass_functions, self.exec_requested
            self.bypass_functions, self.exec_requested = True, name == 'exec'
            try:
                if self.execute_external: return int(self.execute_external(args, replace=name == 'exec'))
                return self._dispatch([Command(args, source=shlex.join(args))])
            finally: self.bypass_functions, self.exec_requested = old_bypass, old_exec
        raise ValueError('unsupported builtin: ' + name)

    def _read(self, args):
        raw, prompt, count, delimiter = False, None, None, '\n'
        while args and args[0].startswith('-'):
            flag, args = args[0], args[1:]
            if flag == '--': break
            if flag == '-r': raw = True
            elif flag in ('-p', '-n', '-d'):
                if not args: raise ValueError(flag + ': argument required')
                value, args = args[0], args[1:]
                if flag == '-p': prompt = value
                elif flag == '-n': count = int(value)
                else: delimiter = value[:1] or '\x00'
            else: raise ValueError('unsupported read option: ' + flag)
        names = args or ['REPLY']
        if any(not re.fullmatch(r'[A-Za-z_]\w*', n) for n in names): raise ValueError('invalid variable name')
        if prompt: print(prompt, file=self.stderr, end='', flush=True)
        chars, eof, escaped = [], False, False
        while count is None or len(chars) < count:
            char = self.stdin.read(1)
            if not char: eof = True; break
            if escaped:
                escaped = False
                if char != '\n': chars.append((char, True))
            elif char == '\\' and not raw: escaped = True
            elif char == delimiter: break
            else: chars.append((char, False))
        value = ''.join(c for c, _ in chars)
        if not args: self._assign('REPLY', value)
        else:
            ifs = self.state.variables.get('IFS', ' \t\n')
            whitespace = set(ifs) & set(' \t\n')
            def is_space(item):
                return not item[1] and item[0] in whitespace
            while chars and is_space(chars[0]): chars.pop(0)
            while chars and is_space(chars[-1]): chars.pop()
            for index, name in enumerate(names):
                if index == len(names) - 1 or not ifs:
                    self._assign(name, ''.join(c for c, _ in chars))
                    chars = []
                    continue
                boundary = next((i for i, (c, protected) in enumerate(chars) if not protected and c in ifs), len(chars))
                self._assign(name, ''.join(c for c, _ in chars[:boundary]))
                chars = chars[boundary:]
                while chars and is_space(chars[0]): chars.pop(0)
                if chars and not chars[0][1] and chars[0][0] in ifs:
                    chars.pop(0)
                    while chars and is_space(chars[0]): chars.pop(0)
        return 1 if eof else 0

    def _directories(self, name, args):
        stack = self.state.directory_stack
        if name == 'dirs':
            if args == ['-c']: stack.clear(); return 0
            if args and args not in (['-p'], ['-v'], ['-l']): raise ValueError('unsupported dirs option')
            values = [os.getcwd(), *stack]
            if args == ['-v']:
                for index, item in enumerate(values): self._print(index, item)
            else: self._print(('\n' if args == ['-p'] else ' ').join(values))
            return 0
        if len(args) > 1: raise ValueError('too many arguments')
        previous = os.getcwd()
        if args and re.fullmatch(r'[+-]\d+', args[0]):
            values = [previous, *stack]
            index = int(args[0][1:])
            if args[0][0] == '-': index = len(values) - 1 - index
            if not 0 <= index < len(values): raise ValueError('directory stack index out of range')
            if name == 'pushd':
                values = values[index:] + values[:index]
                os.chdir(values[0])
            else:
                if len(values) == 1: raise ValueError('directory stack empty')
                values.pop(index)
                if index == 0: os.chdir(values[0])
            stack[:] = values[1:]
            self.state.variables['OLDPWD'] = previous
            self.state.variables['PWD'] = os.getcwd()
            self._print(' '.join([os.getcwd(), *stack]))
            return 0
        if name == 'popd' and args: raise ValueError('expected a directory stack index')
        if name == 'pushd':
            if args:
                os.chdir(args[0]); stack.insert(0, previous)
            elif stack:
                target = stack[0]; os.chdir(target); stack[0] = previous
            else: raise ValueError('directory stack empty')
        else:
            if not stack: raise ValueError('directory stack empty')
            os.chdir(stack[0]); stack.pop(0)
        self.state.variables['OLDPWD'] = previous
        self.state.variables['PWD'] = os.getcwd()
        self._print(' '.join([os.getcwd(), *stack])); return 0

    def _test(self, source):
        tree = parse(source, '<test>')
        node = tree.root_node.named_children[0]
        expander = Expander(self)
        double = source.startswith('[[')
        def text(n): return source.encode()[n.start_byte:n.end_byte].decode()
        def value(n): return expander.scalar(text(n))
        def test(n):
            if n.type == 'binary_expression':
                left, right = n.child_by_field_name('left'), n.child_by_field_name('right')
                op_node = n.child_by_field_name('operator')
                op = text(op_node) if op_node else next((text(c) for c in n.children if not c.is_named), '')
                if op in ('&&', '-a'): return test(left) and test(right)
                if op in ('||', '-o'): return test(left) or test(right)
                a = value(left)
                b = expander.pattern(text(right)) if double and op in ('=', '==', '!=') else value(right)
                if op in ('=', '=='): return fnmatch.fnmatchcase(a, b) if double else a == b
                if op == '!=': return not (fnmatch.fnmatchcase(a, b) if double else a == b)
                if op == '=~': return re.search(b, a) is not None
                if op in ('<', '>'): return a < b if op == '<' else a > b
                if op in ('-eq', '-ne', '-lt', '-le', '-gt', '-ge'):
                    a, b = arithmetic(a, self.state), arithmetic(b, self.state)
                    return {'-eq': a == b, '-ne': a != b, '-lt': a < b, '-le': a <= b, '-gt': a > b, '-ge': a >= b}[op]
                if op in ('-nt', '-ot'): return os.path.getmtime(a) > os.path.getmtime(b) if op == '-nt' else os.path.getmtime(a) < os.path.getmtime(b)
                if op == '-ef': return os.path.samefile(a, b)
                raise ValueError('unsupported test operator: ' + op)
            if n.type == 'unary_expression':
                op = text(n.children[0]); a = value(n.named_children[-1])
                if op == '!': return not test(n.named_children[-1])
                predicates = {'-n': bool, '-z': lambda x: not x, '-e': os.path.exists, '-f': os.path.isfile, '-d': os.path.isdir, '-L': os.path.islink, '-h': os.path.islink, '-s': lambda x: os.path.getsize(x) > 0, '-r': lambda x: os.access(x, os.R_OK), '-w': lambda x: os.access(x, os.W_OK), '-x': lambda x: os.access(x, os.X_OK), '-v': lambda x: x in self.state.variables, '-t': lambda x: os.isatty(int(x))}
                if op not in predicates: raise ValueError('unsupported test operator: ' + op)
                try: return predicates[op](a)
                except OSError: return False
            if n.type == 'parenthesized_expression': return test(n.named_children[0])
            return bool(value(n))
        children = node.named_children
        return int(not (test(children[0]) if children else False))


def preview(source, state=None):
    """Pure all-branch inspection. Unknown dynamic values remain visibly uncertain."""
    tree = parse(source)
    runtime = ShellRuntime(lambda *_: (_ for _ in ()).throw(RuntimeError('preview cannot execute')), state=ShellState.from_snapshot((state or ShellState()).snapshot()), stdout=io.StringIO(), stderr=io.StringIO())
    runtime._contexts.append((source.encode(), '<preview>'))
    commands, uncertainties = [], []
    def find_dynamic(node):
        if node.type in ('command_substitution', 'process_substitution', 'arithmetic_expansion'):
            uncertainties.append('dynamic expansion: ' + runtime._text(node))
        for child in node.named_children: find_dynamic(child)
    find_dynamic(tree.root_node)
    expander = Expander(runtime, preview=True, uncertainties=uncertainties)
    simple = {'command', 'variable_assignment', 'variable_assignments', 'declaration_command', 'unset_command', 'test_command'}
    def walk(node):
        if node.type == 'redirected_statement':
            body = node.child_by_field_name('body')
            if body is None or body.type in simple:
                commands.append(runtime._command(node, expander))
                for redirect in node.named_children:
                    if redirect.type == 'heredoc_redirect':
                        for child in redirect.named_children:
                            if child.type == 'pipeline':
                                for stage in child.named_children: walk(stage)
                            elif redirect.child_by_field_name('right') == child:
                                walk(child)
                return
            uncertainties.append('compound redirection and control flow')
        if node.type in simple:
            command = runtime._command(node, expander)
            commands.append(command)
            if command.argv and command.argv[0] in runtime.state.aliases:
                uncertainties.append('alias expansion: ' + command.argv[0])
            if command.argv and command.argv[0] in runtime.state.functions:
                uncertainties.append('function call: ' + command.argv[0])
            return
        if node.type in {'if_statement', 'while_statement', 'for_statement', 'case_statement', 'list', 'c_style_for_statement', 'function_definition', 'subshell'}:
            uncertainties.append('control flow: ' + node.type)
        if node.type == 'compound_statement' and runtime._text(node).startswith('(('):
            uncertainties.append('arithmetic statement'); commands.append(runtime._command(node, expander)); return
        for child in node.named_children:
            if child.type not in ('comment', 'variable_name', 'word', 'string', 'raw_string', 'number', 'simple_expansion', 'expansion', 'command_substitution'):
                walk(child)
    try: walk(tree.root_node)
    finally: runtime._contexts.pop()
    return commands, list(dict.fromkeys(uncertainties))
