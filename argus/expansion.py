"""Shell word expansion with quote provenance; expansion data is never reparsed as code."""
from __future__ import annotations

import fnmatch
import glob
import os
import re
from dataclasses import dataclass

from tree_sitter import Language, Parser
import tree_sitter_bash


class ExpansionError(ValueError):
    pass


_NAME = re.compile(r"[a-zA-Z_][a-zA-Z_0-9]*")


def _balanced(text, start, opening, closing):
    depth, quote, i = 1, None, start
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if not depth:
                return i
        i += 1
    raise ExpansionError("unclosed expansion")


def brace_expand(text):
    """Expand unquoted comma and integer/character range braces before parameters."""
    quote, i = None, 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "{" and (i == 0 or text[i - 1] != "$"):
            try:
                end = _balanced(text, i + 1, "{", "}")
            except ExpansionError:
                i += 1
                continue
            body = text[i + 1:end]
            parts, depth, start = [], 0, 0
            for j, c in enumerate(body):
                if c == "{": depth += 1
                elif c == "}": depth -= 1
                elif c == "," and depth == 0:
                    parts.append(body[start:j]); start = j + 1
            if parts:
                parts.append(body[start:])
            else:
                match = re.fullmatch(r"(-?\d+|[a-zA-Z])\.\.(-?\d+|[a-zA-Z])(?:\.\.(-?\d+))?", body)
                if match:
                    first, last, step = match.groups()
                    numeric = first.lstrip('-').isdigit() and last.lstrip('-').isdigit()
                    if not numeric and not (len(first) == len(last) == 1):
                        i = end + 1; continue
                    a, b = (int(first), int(last)) if numeric else (ord(first), ord(last))
                    stride = abs(int(step or 1)) or 1
                    stride *= 1 if b >= a else -1
                    width = max(len(first.lstrip('-')), len(last.lstrip('-'))) if numeric and (first.lstrip('-').startswith('0') or last.lstrip('-').startswith('0')) else 0
                    parts = [(('-' if n < 0 else '') + str(abs(n)).zfill(width)) if numeric else chr(n) for n in range(a, b + (1 if stride > 0 else -1), stride)]
            if parts:
                return [item for part in parts for item in brace_expand(text[:i] + part + text[end + 1:])]
        i += 1
    return [text]


def arithmetic(expression, state, *, mutate=True, _seen=None):
    """Parse shell integer arithmetic, evaluating only selected logical branches."""
    expression = re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", lambda m: m.group(1) or m.group(2), expression.strip())
    if not expression:
        return 0
    seen = set() if _seen is None else _seen
    token_re = re.compile(r"\s*(\d+#[0-9A-Za-z@_]+|0[xX][0-9a-fA-F]+|\d+|[A-Za-z_]\w*|\*\*=|<<=|>>=|\+\+|--|\*\*|&&|\|\||==|!=|<=|>=|<<|>>|[+*/%&|^\-]=|[()+*/%&|^~!<>=?:,\-])")
    tokens, offset = [], 0
    while offset < len(expression):
        match = token_re.match(expression, offset)
        if match is None:
            if not expression[offset:].strip(): break
            raise ExpansionError('invalid arithmetic near ' + repr(expression[offset:]))
        tokens.append(match[1]); offset = match.end()
    position = 0
    precedence = {',': 0, '=': 1, '+=': 1, '-=': 1, '*=': 1, '/=': 1, '%=': 1, '**=': 1, '<<=': 1, '>>=': 1, '&=': 1, '|=': 1, '^=': 1, '||': 3, '&&': 4, '|': 5, '^': 6, '&': 7, '==': 8, '!=': 8, '<': 9, '>': 9, '<=': 9, '>=': 9, '<<': 10, '>>': 10, '+': 11, '-': 11, '*': 12, '/': 12, '%': 12, '**': 13}
    assignments = {op for op, priority in precedence.items() if priority == 1}
    def number(token):
        if '#' in token:
            base, digits = token.split('#', 1); base = int(base)
            if not 2 <= base <= 64: raise ExpansionError('invalid arithmetic base')
            alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_'
            value = 0
            for char in digits:
                digit = alphabet.find(char.lower() if base <= 36 else char)
                if not 0 <= digit < base: raise ExpansionError('invalid digit for arithmetic base')
                value = value * base + digit
            return value
        return int(token, 16 if token.lower().startswith('0x') else 8 if len(token) > 1 and token.startswith('0') else 10)
    def expression_node(minimum=0):
        nonlocal position
        if position == len(tokens): raise ExpansionError('missing arithmetic operand')
        token = tokens[position]; position += 1
        if token == '(':
            left = expression_node()
            if position == len(tokens) or tokens[position] != ')': raise ExpansionError('unclosed arithmetic parentheses')
            position += 1
        elif token in ('+', '-', '!', '~', '++', '--'):
            left = ('unary', token, expression_node(14))
        elif _NAME.fullmatch(token):
            left = ('name', token)
        elif token[0].isdigit():
            left = ('number', number(token))
        else:
            raise ExpansionError('invalid arithmetic operand: ' + token)
        while position < len(tokens):
            op = tokens[position]
            if op in ('++', '--') and 15 >= minimum:
                position += 1; left = ('postfix', op, left); continue
            if op == '?' and 2 >= minimum:
                position += 1; yes = expression_node()
                if position == len(tokens) or tokens[position] != ':': raise ExpansionError('missing arithmetic ternary colon')
                position += 1
                left = ('ternary', left, yes, expression_node(2)); continue
            priority = precedence.get(op, -1)
            if priority < minimum: break
            position += 1
            right = expression_node(priority if op in assignments or op == '**' else priority + 1)
            if op in assignments and left[0] != 'name': raise ExpansionError('assignment needs an arithmetic variable')
            left = ('assign' if op in assignments else 'binary', op, left, right)
        return left
    def read_name(name):
        if name in seen: raise ExpansionError('recursive arithmetic variable: ' + name)
        return arithmetic(state.variables.get(name, '0') or '0', state, mutate=mutate, _seen=seen | {name})
    def write_name(name, value):
        if mutate:
            if name in getattr(state, 'readonly', set()): raise ExpansionError(name + ': readonly variable')
            state.variables[name] = str(value)
        return value
    def binary(op, a, b):
        if op == '+': return a + b
        if op == '-': return a - b
        if op == '*': return a * b
        if op in ('/', '%'):
            quotient = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
            return quotient if op == '/' else a - quotient * b
        if op == '**':
            if b < 0: raise ExpansionError('negative arithmetic exponent')
            return a ** b
        if op == '<<': return a << b
        if op == '>>': return a >> b
        if op == '&': return a & b
        if op == '|': return a | b
        if op == '^': return a ^ b
        if op == '==': return int(a == b)
        if op == '!=': return int(a != b)
        if op == '<': return int(a < b)
        if op == '<=': return int(a <= b)
        if op == '>': return int(a > b)
        if op == '>=': return int(a >= b)
        raise ExpansionError('unsupported arithmetic operator: ' + op)
    def evaluate(node):
        kind = node[0]
        if kind == 'number': return node[1]
        if kind == 'name': return read_name(node[1])
        if kind in ('unary', 'postfix'):
            op, target = node[1:]
            if op in ('++', '--'):
                if target[0] != 'name': raise ExpansionError('increment needs an arithmetic variable')
                old = read_name(target[1])
                new = write_name(target[1], old + (1 if op == '++' else -1))
                return old if kind == 'postfix' else new
            value = evaluate(target)
            return {'+': lambda: value, '-': lambda: -value, '!': lambda: int(not value), '~': lambda: ~value}[op]()
        if kind == 'ternary': return evaluate(node[2] if evaluate(node[1]) else node[3])
        op, left, right = node[1:]
        if kind == 'assign':
            value = evaluate(right)
            return write_name(left[1], value if op == '=' else binary(op[:-1], read_name(left[1]), value))
        a = evaluate(left)
        if op == '&&': return int(bool(a) and bool(evaluate(right)))
        if op == '||': return int(bool(a) or bool(evaluate(right)))
        if op == ',': return evaluate(right)
        return binary(op, a, evaluate(right))
    try:
        root = expression_node()
        if position != len(tokens): raise ExpansionError('unexpected arithmetic token: ' + tokens[position])
        return evaluate(root)
    except (ValueError, ZeroDivisionError, OverflowError) as error:
        raise ExpansionError(f'invalid arithmetic: {expression}: {error}') from error


@dataclass
class _Field:
    chars: list
    forced: bool = False


class Expander:
    def __init__(self, runtime, *, preview=False, uncertainties=None):
        self.runtime = runtime
        self.state = runtime.state
        self.preview = preview
        self.uncertainties = uncertainties if uncertainties is not None else []
        self._parser = None

    def _node_end(self, text, start, kind):
        # Grammar matching handles ')' in case patterns, nested substitutions,
        # comments and heredocs, which a parenthesis counter cannot distinguish.
        if self._parser is None:
            self._parser = Parser(Language(tree_sitter_bash.language()))
        remainder = text[start:]
        from .language import _grammar_source
        root = self._parser.parse(_grammar_source(remainder).encode()).root_node
        def find(node):
            if node.start_byte != 0:
                return None
            if node.type == kind and not node.has_error:
                return node
            for child in node.named_children:
                found = find(child)
                if found is not None: return found
            return None
        node = find(root)
        if node is None:
            raise ExpansionError('invalid or unclosed ' + kind.replace('_', ' '))
        return start + len(remainder.encode()[:node.end_byte].decode())

    def special(self, name):
        s = self.state
        if self.preview and name != '$':
            self.uncertainties.append('parameter value may change before execution: ' + name)
            if _NAME.fullmatch(name) and name not in s.variables:
                return '${' + name + '}'
        if name == '?': return str(s.last_status)
        if name == '$': return str(s.pid)
        if name == '!': return str(s.last_background or '')
        if name == '#': return str(len(s.positional))
        if name == '-':
            flags = {'a': 'allexport', 'e': 'errexit', 'f': 'noglob', 'u': 'nounset', 'x': 'xtrace', 'n': 'noexec', 'C': 'noclobber'}
            return ''.join(flag for flag, option in flags.items() if s.options.get(option))
        if name == '0': return s.argv0
        if name.isdigit(): return s.positional[int(name)-1] if 0 < int(name) <= len(s.positional) else ''
        if name in ('@', '*'): return list(s.positional)
        if name in s.variables: return s.variables[name]
        if s.options.get('nounset') or s.options.get('u'):
            raise ExpansionError(f'{name}: unbound variable')
        return ''

    def parameter(self, body):
        if body.startswith('#') and len(body) > 1:
            value = self.special(body[1:]); return str(len(value))
        match = re.match(r"([A-Za-z_]\w*|\d+|[@*?#$!\-])(?:(:?[-+=?]|##?|%%?)(.*))?$", body, re.S)
        if not match: raise ExpansionError('unsupported parameter expansion: ${' + body + '}')
        name, op, word = match.groups()
        if op is None:
            value = self.special(name)
            return self.state.variables.get('IFS', ' \t\n')[:1].join(value) if name == '*' else value
        exists = name in self.state.variables or name in '@*?#$!-' or name.isdigit() and int(name) <= len(self.state.positional)
        value = self.state.variables.get(name, '') if _NAME.fullmatch(name) else self.special(name)
        absent = not exists or (op.startswith(':') and value == '')
        kind = op[-1]
        if kind in '-+?=' and op not in ('#', '##', '%', '%%'):
            use = absent if kind != '+' else not absent
            if not use: return '' if kind == '+' else value
            replacement = self.scalar(word)
            if kind == '?':
                if self.preview:
                    self.uncertainties.append('parameter may abort execution: ' + name)
                    return '${' + body + '}'
                raise ExpansionError(f'{name}: {replacement or "parameter is unset or null"}')
            if kind == '=':
                if not _NAME.fullmatch(name): raise ExpansionError('cannot assign special parameter')
                if self.preview: self.uncertainties.append('parameter assignment: ' + name)
                else: self.runtime.assign_parameter(name, replacement)
            return replacement
        pattern = self.pattern(word)
        if isinstance(value, list): value = ' '.join(value)
        indexes = range(len(value) + 1)
        if op in ('##', '%'): indexes = reversed(range(len(value) + 1))
        for index in indexes:
            piece = value[:index] if op.startswith('#') else value[index:]
            if fnmatch.fnmatchcase(piece, pattern):
                return value[index:] if op.startswith('#') else value[:index]
        return value

    def scalar(self, text, *, heredoc=False):
        return self.state.variables.get('IFS', ' \t\n')[:1].join(self.word(text, split=False, globbing=False, braces=False, heredoc=heredoc))

    def pattern(self, text):
        return ''.join(self.word(text, split=False, globbing=False, braces=False, pattern_mode=True))

    def word(self, text, *, split=True, globbing=True, braces=True, heredoc=False, pattern_mode=False):
        result = []
        for variant in brace_expand(text) if braces else [text]:
            fields = [_Field([])]
            quote = None
            i = 0
            def append(value, protected=False, expansion=False):
                if isinstance(value, list):
                    if not value: return
                    protected_list = quote == '"'
                    fields[-1].forced |= protected_list
                    fields[-1].chars.extend((c, protected_list, not protected_list) for c in value[0])
                    for item in value[1:]:
                        fields.append(_Field([(c, protected_list, not protected_list) for c in item], protected_list))
                    return
                fields[-1].chars.extend((c, protected, expansion) for c in value)
                if protected: fields[-1].forced = True
            while i < len(variant):
                c = variant[i]
                if quote == "'":
                    if c == "'": quote = None
                    else: append(c, True)
                    i += 1; continue
                if not heredoc and c in "'\"" and (quote is None or quote == c):
                    opening = quote is None
                    quote = None if quote else c
                    # Explicit quote markers preserve null fields at the correct
                    # position when an adjacent unquoted expansion splits.
                    if opening and (variant not in ('"$@"', '"${@}"') or self.state.positional):
                        fields[-1].chars.append(('', True, False))
                        fields[-1].forced = True
                    i += 1; continue
                if c == '\\' and i + 1 < len(variant):
                    nxt = variant[i + 1]
                    if nxt == '\n': i += 2; continue
                    if (not quote and not heredoc) or (quote == '"' and nxt in '$`"\\') or (heredoc and nxt in '$`\\'):
                        append(nxt, True); i += 2; continue
                    append(c, bool(quote)); i += 1; continue
                if c == '~' and i == 0 and not quote and not heredoc:
                    end = next((j for j in range(i, len(variant)) if variant[j] == '/'), len(variant))
                    prefix = variant[:end]
                    home = self.state.variables.get('HOME', os.path.expanduser('~')) if prefix == '~' else os.path.expanduser(prefix)
                    append(home, True); i = end; continue
                if c == '$':
                    if variant.startswith('$((', i):
                        end = self._node_end(variant, i, 'arithmetic_expansion')
                        expr = variant[i + 3:end - 2]
                        if self.preview:
                            self.uncertainties.append('arithmetic expansion: ' + expr); value = variant[i:end]
                        else: value = str(self.runtime.evaluate_arithmetic(self.scalar(expr)))
                        append(value, bool(quote) or self.preview, True); i = end; continue
                    if variant.startswith('$(', i):
                        end = self._node_end(variant, i, 'command_substitution')
                        source = variant[i + 2:end - 1]
                        if self.preview:
                            self.uncertainties.append('command substitution: ' + source); value = variant[i:end]
                        else: value = self.runtime.capture(source).rstrip('\n')
                        append(value, bool(quote) or self.preview, True); i = end; continue
                    if variant.startswith('${', i):
                        end = self._node_end(variant, i, 'expansion')
                        append(self.parameter(variant[i + 2:end - 1]), bool(quote), True); i = end; continue
                    match = re.match(r"[A-Za-z_]\w*|[0-9@*?#$!\-]", variant[i + 1:])
                    if match:
                        name = match[0]; value = self.special(name)
                        if name == '*': value = self.state.variables.get('IFS', ' \t\n')[:1].join(value)
                        append(value, bool(quote), True); i += len(name) + 1; continue
                if c == '`':
                    end = self._node_end(variant, i, 'command_substitution')
                    source = re.sub(r'\\([$`\\])', r'\1', variant[i + 1:end - 1])
                    if self.preview: self.uncertainties.append('command substitution: ' + source); value = variant[i:end]
                    else: value = self.runtime.capture(source).rstrip('\n')
                    append(value, bool(quote), True); i = end; continue
                append(c, bool(quote)); i += 1
            if quote: raise ExpansionError('unclosed quote')
            for field in fields:
                split_fields = self._split(field) if split else [field]
                for item in split_fields:
                    value = ''.join(glob.escape(c) if protected and pattern_mode else c for c, protected, _ in item.chars)
                    if '\x00' in value: raise ExpansionError('NUL is not allowed in command arguments')
                    if globbing and any(c in '*?[' and not protected for c, protected, _ in item.chars):
                        pattern = ''.join(glob.escape(c) if protected else c for c, protected, _ in item.chars)
                        matches = sorted(glob.glob(pattern))
                        if matches: result.extend(matches); continue
                        if self.state.options.get('failglob'): raise ExpansionError('no match: ' + value)
                        if self.state.options.get('nullglob'): continue
                    if item.chars or item.forced: result.append(value)
        return result

    def _split(self, field):
        ifs = self.state.variables.get('IFS', ' \t\n')
        if not ifs: return [field]
        result, current, after_separator = [], _Field([], field.forced), False
        for c, protected, expansion in field.chars:
            if not protected and expansion and c in ifs:
                if c in ' \t\n':
                    if current.chars:
                        result.append(current); current = _Field([])
                    after_separator = True
                else:
                    result.append(current); current = _Field([], True); after_separator = True
            else:
                current.chars.append((c, protected, expansion)); after_separator = False
        if current.chars or current.forced and not after_separator: result.append(current)
        return result
