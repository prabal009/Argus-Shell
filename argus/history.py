"""Private, multiline-safe shell history with locked, atomic cross-session merges.

Only new records are merged, never a session's stale snapshot. Deletion therefore
cannot be undone by another session saving its history. A clear advances the
store generation, invalidating additions queued before that clear.
"""

from contextlib import contextmanager
from fnmatch import fnmatchcase
import json
import os
import threading
import uuid

from .config import HISTORY_FILE, HISTORY_LIMIT
from .storage import atomic_write, locked_file, open_private, private_directory, storage_warning
from .utils import redact_text, safe_text
from .i18n import translate

_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


@contextmanager
def _locked(path):
    """Serialize threads and processes; the lock inode is never replaced."""
    key = os.path.abspath(os.fspath(path))
    with _LOCKS_GUARD:
        local = _LOCKS.setdefault(key, threading.RLock())
    with local:
        private_directory(os.path.dirname(key))
        with locked_file(key + '.lock'):
            yield


class History:
    def __init__(self, path=None, limit=HISTORY_LIMIT, *, private=False, ignore=None):
        self.path = os.fspath(HISTORY_FILE if path is None else path)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError('history limit must be a positive integer')
        self.limit = limit
        self.private = bool(private)
        self.ignore = list(ignore or [])
        self.pending = []
        self._records = []
        self._generation = 0
        self._loaded = False
        self._mutex = threading.RLock()

    def _read(self):
        try:
            fd = open_private(self.path, os.O_RDONLY)
        except FileNotFoundError:
            legacy = os.path.join(os.path.dirname(self.path), 'legacy-history')
            if os.path.abspath(self.path) != os.path.abspath(HISTORY_FILE):
                return 0, []
            try:
                fd = open_private(legacy, os.O_RDONLY)
            except FileNotFoundError:
                return 0, []
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            text = stream.read()
        if text.startswith('{'):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                # Legacy commands are allowed to begin with an opening brace.
                data = None
            if isinstance(data, dict) and data.get('format') == 'argus-history-1':
                generation = data['generation']
                records = data['entries']
                if not isinstance(generation, int) or generation < 0 or not isinstance(records, list):
                    raise ValueError('invalid history store')
                clean = []
                for item in records:
                    if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not isinstance(item.get('text'), str):
                        raise ValueError('invalid history record')
                    if self._allowed(item['text'], apply_ignore=False):
                        clean.append({'id': item['id'], 'text': item['text']})
                return generation, clean
        records = []
        for index, line in enumerate(text.splitlines()):
            if self._allowed(line, apply_ignore=False):
                identity = uuid.uuid5(uuid.NAMESPACE_URL, f'{os.path.abspath(self.path)}:{index}:{line}')
                records.append({'id': str(identity), 'text': line})
        return 0, records

    def _allowed(self, text, *, apply_ignore=True):
        return (bool(text.strip()) and '\x00' not in text
                and redact_text(text) == text
                and (not apply_ignore or not any(fnmatchcase(text, rule) for rule in self.ignore)))

    def _write(self, generation, records):
        payload = {'format': 'argus-history-1', 'generation': generation,
                   'entries': records[-self.limit:]}
        atomic_write(self.path, json.dumps(payload, ensure_ascii=True) + '\n', private_parent=False)

    def load(self):
        return self.merge()

    def entries(self):
        with self._mutex:
            if not self._loaded:
                self.load()
            return [item['text'] for item in self._records]

    def add(self, line):
        with self._mutex:
            if self.private or not self._allowed(line):
                return False
            if not self._loaded:
                self.load()
            if self._records and self._records[-1]['text'] == line:
                return False
            record = {'id': str(uuid.uuid4()), 'text': line}
            self.pending.append((self._generation, record))
            self._records = (self._records + [record])[-self.limit:]
            return self.save()

    def save(self):
        with self._mutex:
            if not self.pending:
                return True
            try:
                with _locked(self.path):
                    generation, records = self._read()
                    known = {item['id'] for item in records}
                    records.extend(item for epoch, item in self.pending
                                   if epoch == generation and item['id'] not in known)
                    records = records[-self.limit:]
                    self._write(generation, records)
                    self._generation, self._records = generation, records
                    self.pending.clear()
                    self._loaded = True
                return True
            except (OSError, UnicodeError, ValueError) as error:
                storage_warning('history write failed', error)
                return False

    def merge(self):
        with self._mutex:
            if self.pending and not self.save():
                return [item['text'] for item in self._records]
            try:
                with _locked(self.path):
                    self._generation, records = self._read()
                    self._records = records[-self.limit:]
                    self._loaded = True
            except (OSError, UnicodeError, ValueError) as error:
                storage_warning('history read failed', error)
            return [item['text'] for item in self._records]

    def search(self, pattern):
        return [(index, text) for index, text in enumerate(self.entries(), 1)
                if pattern.casefold() in text.casefold()]

    def delete(self, index):
        with self._mutex:
            entries = self.entries()
            if isinstance(index, bool) or not 1 <= index <= len(entries):
                return False
            identity = self._records[index - 1]['id']
            try:
                with _locked(self.path):
                    generation, records = self._read()
                    records = [item for item in records if item['id'] != identity]
                    self._write(generation, records)
                    self.pending = [(epoch, item) for epoch, item in self.pending if item['id'] != identity]
                    self._generation, self._records = generation, records[-self.limit:]
                return True
            except (OSError, UnicodeError, ValueError) as error:
                storage_warning('history delete failed', error)
                return False

    def clear(self):
        with self._mutex:
            try:
                with _locked(self.path):
                    generation, _ = self._read()
                    self._write(generation + 1, [])
                    self._generation, self._records = generation + 1, []
                    self.pending.clear()
                    self._loaded = True
                return True
            except (OSError, UnicodeError, ValueError) as error:
                storage_warning('history clear failed', error)
                return False

    def set_private(self, enabled):
        self.private = bool(enabled)
        if enabled:
            self.pending.clear()

    def command(self, args=(), *, stdout=None, locale=None):
        """Consumer API used by the shell's history builtin (without argv[0])."""
        import sys
        stream = sys.stdout if stdout is None else stdout
        args = list(args)
        action = args[0] if args else 'show'
        tail = args[1:]
        tr = lambda key, **values: translate(key, locale, **values)
        try:
            if action in ('show', 'search'):
                if (action == 'show' and tail) or (action == 'search' and not tail):
                    raise ValueError
                rows = self.search(' '.join(tail)) if action == 'search' else list(enumerate(self.entries(), 1))
                for index, text in rows:
                    print(f'{index:5}  {safe_text(text)}', file=stream)
                return 0
            if action in ('delete', '-d') and len(tail) == 1:
                return 0 if self.delete(int(tail[0])) else 1
            if action in ('clear', '-c') and not tail:
                return 0 if self.clear() else 1
            if action == 'merge' and not tail:
                self.merge()
                return 0
            if action == 'private' and len(tail) <= 1:
                if tail:
                    if tail[0] not in ('on', 'off'):
                        raise ValueError
                    self.set_private(tail[0] == 'on')
                print(tr('history.private', state=tr('on' if self.private else 'off')), file=stream)
                return 0
            if action == 'ignore':
                if not tail:
                    for rule in self.ignore:
                        print(safe_text(rule), file=stream)
                    return 0
                if len(tail) == 2 and tail[0] == 'add':
                    if tail[1] not in self.ignore:
                        self.ignore.append(tail[1])
                    return 0
                if len(tail) == 2 and tail[0] == 'remove':
                    self.ignore.remove(tail[1])
                    return 0
            if action == 'limit' and len(tail) <= 1:
                if tail:
                    limit = int(tail[0])
                    if limit < 1:
                        raise ValueError
                    self.limit = limit
                    self.merge()
                    with _locked(self.path):
                        generation, records = self._read()
                        self._write(generation, records)
                print(self.limit, file=stream)
                return 0
        except (ValueError, TypeError, OSError):
            pass
        print(tr('history.usage'), file=stream)
        return 2
