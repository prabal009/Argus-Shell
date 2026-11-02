"""Real local persistence, isolated in explicitly configured platform paths."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class AuditStorageTests(unittest.TestCase):
    def scenario(self, script):
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home, PYTHONPATH=str(REPO),
                       ARGUS_CONFIG_HOME=str(Path(home, 'config')),
                       ARGUS_STATE_HOME=str(Path(home, 'state')),
                       ARGUS_DATA_HOME=str(Path(home, 'data')))
            result = subprocess.run(
                [sys.executable, '-c', 'from argus.config import prepare_paths\nprepare_paths()\n' + script],
                cwd=home, env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result

    def test_locked_database_warns_while_best_effort_command_still_runs(self):
        self.scenario('''import io, sqlite3
from contextlib import redirect_stderr, redirect_stdout
from argus.config import ARGUS_DATABASE
from argus.database import initialize_database
from argus.main import execute_command
assert initialize_database()
lock=sqlite3.connect(ARGUS_DATABASE)
lock.execute('BEGIN EXCLUSIVE')
errors, output = io.StringIO(), io.StringIO()
try:
    with redirect_stderr(errors), redirect_stdout(output):
        assert execute_command('pwd') == 0
finally:
    lock.rollback(); lock.close()
assert 'command audit write failed' in errors.getvalue(), errors.getvalue()
assert 'best-effort' in errors.getvalue()
assert output.getvalue().strip()
''')

    def test_configurable_retention_keeps_active_starts_and_bounds_finalized_rows(self):
        self.scenario('''from contextlib import closing
from argus.config import save_settings
from argus.database import initialize_database,get_database_connection,prune_records
assert save_settings({'retention_records': 3})
assert initialize_database()
with closing(get_database_connection()) as connection, connection:
    connection.executemany(
        "INSERT INTO command_audit(timestamp,username,cwd,command,state) VALUES('t','u','/','c',?)",
        [('running',),('stopped',)] + [('completed',)]*7)
    prune_records(connection,'command_audit')
    assert connection.execute("SELECT count(*) FROM command_audit WHERE state='completed'").fetchone()[0] == 3
    assert connection.execute("SELECT count(*) FROM command_audit WHERE state IN ('running','stopped')").fetchone()[0] == 2
''')

    def test_age_retention_and_zero_count_limit(self):
        self.scenario('''from contextlib import closing
from argus.config import save_settings
from argus.database import initialize_database,get_database_connection,prune_records
assert save_settings({'retention_records': 0, 'retention_days': 2})
assert initialize_database()
with closing(get_database_connection()) as connection, connection:
    for state in ('completed','running','stopped'):
        connection.execute("INSERT INTO command_audit(timestamp,username,cwd,command,state) VALUES(datetime('now','-3 days'),'u','/','old',?)", (state,))
    connection.executemany("INSERT INTO command_audit(timestamp,username,cwd,command,state) VALUES(datetime('now'),'u','/','recent','completed')", [()]*5)
    prune_records(connection,'command_audit')
    assert connection.execute("SELECT count(*) FROM command_audit WHERE command='old' AND state='completed'").fetchone()[0] == 0
    assert connection.execute("SELECT count(*) FROM command_audit WHERE state IN ('running','stopped')").fetchone()[0] == 2
    assert connection.execute("SELECT count(*) FROM command_audit WHERE command='recent'").fetchone()[0] == 5
    try:
        prune_records(connection,'sqlite_master')
    except ValueError:
        pass
    else:
        raise AssertionError('arbitrary retention table accepted')
''')

    def test_completion_prunes_newly_finalized_records_while_input_is_idle(self):
        self.scenario('''from contextlib import closing
from argus.config import save_settings
from argus.database import initialize_database,get_database_connection
from argus.audit import audit_command,update_audit
assert save_settings({'retention_records': 3})
assert initialize_database()
for i in range(3):
    assert audit_command('printf old-' + str(i), exit_status=0)
audit_id=audit_command('printf new')
assert audit_id
assert update_audit(audit_id,exit_status=0,duration_ms=1,state='completed')
with closing(get_database_connection()) as connection:
    assert connection.execute("SELECT count(*) FROM command_audit WHERE state='completed'").fetchone()[0] == 3
    assert connection.execute("SELECT state FROM command_audit WHERE id=?",(audit_id,)).fetchone()[0] == 'completed'
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert connection.execute('SELECT state FROM command_events WHERE audit_id=? ORDER BY id DESC LIMIT 1',(audit_id,)).fetchone()[0] == 'completed'
''')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires filesystem FIFOs')
    def test_fifo_policy_does_not_block_or_replace_current_policy(self):
        self.scenario('''import os,copy
from argus.config import ARGUS_POLICY_FILE
from argus.database import initialize_database
from argus.security import security_policy,load_policy_from_disk
assert initialize_database()
os.mkfifo(ARGUS_POLICY_FILE,0o600)
before=copy.deepcopy(security_policy)
try:
    load_policy_from_disk()
except (OSError,ValueError):
    pass
else:
    raise AssertionError('FIFO policy accepted')
assert security_policy==before
''')

    def test_common_credential_forms_are_redacted_without_rewriting_commands(self):
        self.scenario('''from argus.utils import redact_text,safe_text
for source, secret in [
    ('export API_TOKEN="two secret words"','two secret words'),
    ('tool --password "two secret words"','two secret words'),
    ('tool --token=credential-value','credential-value'),
    ('tool https://user:credential-value@example.invalid/path','credential-value'),
]:
    result=redact_text(source)
    assert secret not in result, result
    assert '[REDACTED]' in result
assert redact_text('printf ordinary')=='printf ordinary'
assert '\\x1b' not in safe_text('bad\\x1b[2J')
''')

    def test_signed_local_audit_tracks_lifecycle_and_detects_tampering(self):
        self.scenario('''import json, os
from pathlib import Path
from argus.config import get_settings, save_settings
from argus.database import initialize_database
from argus.audit import audit_command,update_audit
from argus.integrity import verify
assert save_settings({'audit_sign': True})
assert initialize_database()
audit_id=audit_command('export API_TOKEN="signed-secret"')
assert audit_id and update_audit(audit_id,exit_status=0,duration_ms=2)
path=Path(get_settings()['audit_chain'])
original=path.read_bytes()
assert b'signed-secret' not in original
records=[json.loads(line) for line in original.splitlines()]
assert [record['record']['event'] for record in records] == ['command','lifecycle']
assert all(record['record']['audit_id'] == audit_id for record in records)
state=verify(path)
assert state.valid and state.count == 2, state
assert state.trust == 'user-owned-local-key'
trusted=verify(path,public_key=state.public_key,anchor=state.anchor)
assert trusted.valid and trusted.trust == 'external-key-and-anchor'
records[0]['record']['command']='forged'
path.write_text(''.join(json.dumps(record)+'\\n' for record in records))
assert not verify(path,public_key=state.public_key,anchor=state.anchor).valid
path.write_bytes(original.splitlines(keepends=True)[0])
assert not verify(path,public_key=state.public_key,anchor=state.anchor).valid
if os.name == 'posix':
    assert Path(str(path)+'.key').stat().st_mode & 0o077 == 0
''')

    def test_plain_archive_uses_configured_directory_and_time_filters(self):
        self.scenario('''import json
from pathlib import Path
from contextlib import closing
from argus.config import get_settings,save_settings
from argus.database import initialize_database,get_database_connection
from argus.audit import audit_command,archive_records
assert save_settings({'archive_encrypted': False})
assert initialize_database()
old=audit_command('printf old',exit_status=0)
new=audit_command('tool --token=archive-secret',exit_status=0)
with closing(get_database_connection()) as connection, connection:
    connection.execute("UPDATE command_audit SET timestamp='2000-01-01T00:00:00' WHERE id=?",(old,))
    connection.execute("UPDATE command_events SET timestamp='2000-01-01T00:00:00' WHERE audit_id=?",(old,))
result=archive_records(since='2001-01-01T00:00:00',until='2999-01-01T00:00:00')
path=Path(result['path'])
assert path.parent == Path(get_settings()['archive_dir'])
assert result['encrypted'] is False
content=path.read_text()
assert 'archive-secret' not in content
archive=json.loads(content)
assert archive['schema_version'] == 1 and archive['created_at']
assert set(archive['tables']) == {'command_audit','command_events','suspicious_events','security_actions'}
assert result['counts'] == {name: len(rows) for name,rows in archive['tables'].items()}
assert [row['id'] for row in archive['tables']['command_audit']] == [new]
assert [row['audit_id'] for row in archive['tables']['command_events']] == [new]
''')

    def test_encrypted_archive_authenticates_and_never_writes_key_to_disk(self):
        # The keyring boundary is an ephemeral backend; archive encryption/decryption
        # and authentication use the real production APIs and cryptography library.
        self.scenario('''import base64,json
from pathlib import Path
import keyring
from keyring.backend import KeyringBackend
from argus.config import ARGUS_STATE_DIR,get_settings
from argus.database import initialize_database
from argus.audit import audit_command,archive_records
from argus.integrity import decrypt_archive,IntegrityError
class EphemeralKeyring(KeyringBackend):
    __module__='keyring.backends.SecretService'  # Explicit secure-OS test double.
    priority=1
    def __init__(self): self.values={}
    def get_password(self,service,username): return self.values.get((service,username))
    def set_password(self,service,username,password): self.values[service,username]=password
    def delete_password(self,service,username): del self.values[service,username]
backend=EphemeralKeyring()
keyring.set_keyring(backend)
assert initialize_database()
audit_id=audit_command('printf encrypted-payload',exit_status=0)
result=archive_records(key_id='acceptance')
assert result['encrypted'] is True
source=Path(result['path'])
assert b'encrypted-payload' not in source.read_bytes()
key=backend.get_password('argus.audit.archive','acceptance')
assert key and len(base64.b64decode(key)) == 32
for path in Path('.').rglob('*'):
    if path.is_file(): assert key.encode() not in path.read_bytes(), path
assert not list(Path(ARGUS_STATE_DIR).glob('archive-*.json'))
restored=Path(get_settings()['archive_dir'])/'restored.json'
decrypt_archive(source,restored,key_id='acceptance')
archive=json.loads(restored.read_text())
assert archive['tables']['command_audit'][0]['id'] == audit_id
assert archive['tables']['command_audit'][0]['command'] == 'printf encrypted-payload'
envelope=json.loads(source.read_text())
ciphertext=bytearray(base64.b64decode(envelope['ciphertext']))
ciphertext[-1] ^= 1
envelope['ciphertext']=base64.b64encode(ciphertext).decode()
source.write_text(json.dumps(envelope))
rejected=restored.with_name('rejected.json')
try:
    decrypt_archive(source,rejected)
except IntegrityError:
    pass
else:
    raise AssertionError('tampered encrypted archive accepted')
assert not rejected.exists()
''')

    def test_keyring_failure_has_no_plaintext_archive_fallback(self):
        self.scenario('''from pathlib import Path
import keyring
from keyring.backend import KeyringBackend
from argus.config import ARGUS_STATE_DIR,get_settings
from argus.database import initialize_database
from argus.audit import audit_command,archive_records
from argus.integrity import IntegrityError
class UnavailableKeyring(KeyringBackend):
    __module__='keyring.backends.SecretService'  # Exercise service failure after selection.
    priority=1
    def get_password(self,service,username): raise RuntimeError('no credential service')
    def set_password(self,service,username,password): raise RuntimeError('no credential service')
keyring.set_keyring(UnavailableKeyring())
assert initialize_database()
assert audit_command('printf private-payload',exit_status=0)
try:
    archive_records()
except IntegrityError as error:
    assert 'keyring' in str(error).lower(), error
else:
    raise AssertionError('archive silently bypassed unavailable keyring')
assert not list(Path(get_settings()['archive_dir']).iterdir())
assert not list(Path(ARGUS_STATE_DIR).glob('archive-*.json'))
''')

    def test_plaintext_keyring_is_rejected_before_any_credential_access(self):
        self.scenario('''from pathlib import Path
import keyring
from keyring.backend import KeyringBackend
from argus.config import ARGUS_STATE_DIR,get_settings
from argus.database import initialize_database
from argus.audit import audit_command,archive_records
from argus.integrity import _archive_key,IntegrityError
class PlaintextKeyring(KeyringBackend):
    __module__='keyrings.alt.file'
    priority=10
    def __init__(self): self.calls=[]
    def get_password(self,service,username):
        self.calls.append(('read',service,username))
        return None
    def set_password(self,service,username,password):
        self.calls.append(('write',service,username))
backend=PlaintextKeyring()
keyring.set_keyring(backend)
assert initialize_database()
assert audit_command('printf private-archive-payload',exit_status=0)
for create in (False,True):
    try:
        _archive_key('rejected',create=create)
    except IntegrityError as error:
        assert 'secure' in str(error).lower() and 'keyring' in str(error).lower(), error
    else:
        raise AssertionError('plaintext keyring accepted')
try:
    archive_records()
except IntegrityError:
    pass
else:
    raise AssertionError('archive used a plaintext credential backend')
assert backend.calls == [], backend.calls
assert not list(Path(get_settings()['archive_dir']).iterdir())
assert not list(Path(ARGUS_STATE_DIR).glob('archive-*.json'))
''')

    def test_private_files_are_atomic_and_reject_nonregular_targets(self):
        self.scenario('''import os
from pathlib import Path
from argus.config import ARGUS_STATE_DIR
from argus.storage import private_directory,atomic_write,open_private,locked_file
root=Path(ARGUS_STATE_DIR)/'private'
private_directory(root)
path=root/'record'
atomic_write(path,'first')
atomic_write(path,'second')
assert path.read_text() == 'second'
assert not list(root.glob('.argus-*'))
with locked_file(root/'record.lock') as fd:
    assert os.fstat(fd).st_size >= 0
try:
    open_private(root)
except PermissionError:
    pass
else:
    raise AssertionError('directory accepted as a private file')
if os.name == 'posix':
    assert root.stat().st_mode & 0o077 == 0
    assert path.stat().st_mode & 0o077 == 0
    public=root/'public'
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    try:
        private_directory(public)
    except PermissionError:
        pass
    else:
        raise AssertionError('public directory accepted')
    for kind in ('symlink','hardlink','fifo'):
        target=root/kind
        if kind == 'symlink': target.symlink_to(path)
        elif kind == 'hardlink': os.link(path,target)
        else: os.mkfifo(target,0o600)
        try:
            open_private(target)
        except PermissionError:
            pass
        else:
            raise AssertionError(kind+' accepted as private storage')
        target.unlink()
    assert path.read_text() == 'second'
''')

    @unittest.skipUnless(os.name == 'nt', 'requires real Windows identity and ACL APIs')
    def test_windows_identity_ignores_environment_and_private_acl_works(self):
        self.scenario('''import os
from pathlib import Path
from argus.config import ARGUS_STATE_DIR
from argus.winsecurity import current_sid,current_username,secure_path
from argus.storage import private_directory,atomic_write,open_private
username=current_username()
sid=current_sid()
assert username and sid.startswith('S-1-')
for name in ('USER','USERNAME','LOGNAME'):
    os.environ[name]='argus-forged-environment-identity'
assert current_username() == username
assert current_sid() == sid
root=Path(ARGUS_STATE_DIR)/'windows-private'
private_directory(root)
path=root/'record'
atomic_write(path,'private')
secure_path(path)
fd=open_private(path,os.O_RDONLY)
try:
    assert os.read(fd,7) == b'private'
finally:
    os.close(fd)
''')

    @unittest.skipIf(os.name == 'nt', 'non-Windows guard')
    def test_windows_apis_are_guarded_on_other_platforms(self):
        self.scenario('''from argus.winsecurity import current_username,current_sid,secure_path
for api,args in ((current_username,()),(current_sid,()),(secure_path,('unused',))):
    try:
        api(*args)
    except OSError as error:
        assert 'Windows' in str(error)
    else:
        raise AssertionError('Windows API invoked on a non-Windows host')
''')


if __name__ == '__main__':
    unittest.main()
