"""Consumer tests for settings, platform paths and real legacy migration."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def scenario(self, script, *, platform_paths=False):
        with tempfile.TemporaryDirectory() as home:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith('ARGUS_') and key not in ('XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME')}
            env.update(HOME=home, USERPROFILE=home, PYTHONPATH=str(REPO),
                       XDG_CONFIG_HOME=str(Path(home, 'xdg-config')),
                       XDG_STATE_HOME=str(Path(home, 'xdg-state')),
                       XDG_DATA_HOME=str(Path(home, 'xdg-data')),
                       APPDATA=str(Path(home, 'roaming')), LOCALAPPDATA=str(Path(home, 'local')))
            if not platform_paths:
                env.update(ARGUS_CONFIG_HOME=str(Path(home, 'config')),
                           ARGUS_STATE_HOME=str(Path(home, 'state')),
                           ARGUS_DATA_HOME=str(Path(home, 'data')))
            result = subprocess.run([sys.executable, '-c', script], cwd=home, env=env,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result

    def test_explicit_config_data_and_state_paths_are_independent(self):
        self.scenario('''import json,os
from pathlib import Path
from argus import config
config.prepare_paths()
assert config.ARGUS_CONFIG_DIR == os.environ['ARGUS_CONFIG_HOME']
assert config.ARGUS_STATE_DIR == os.environ['ARGUS_STATE_HOME']
assert config.ARGUS_ASSET_DIR == os.environ['ARGUS_DATA_HOME']
assert config.ARGUS_DATA_DIR == config.ARGUS_STATE_DIR
assert Path(config.ARGUS_POLICY_FILE).parent == Path(config.ARGUS_CONFIG_DIR)
assert Path(config.SETTINGS_FILE).parent == Path(config.ARGUS_CONFIG_DIR)
assert Path(config.ARGUS_DATABASE).parent == Path(config.ARGUS_STATE_DIR)
assert Path(config.HISTORY_FILE).parent == Path(config.ARGUS_STATE_DIR)
assert Path(config.get_settings()['archive_dir']).parent == Path(config.ARGUS_ASSET_DIR)
assert Path(config.get_settings()['audit_chain']).parent == Path(config.ARGUS_STATE_DIR)
assert json.loads(Path(config.ARGUS_STATE_DIR,'migration.json').read_text()) == {'schema_version':1,'imported':[]}
assert not Path.home().joinpath('.argus').exists()
assert not Path.home().joinpath('.argus_history').exists()
if os.name == 'posix':
    for root in (config.ARGUS_CONFIG_DIR,config.ARGUS_STATE_DIR,config.ARGUS_ASSET_DIR):
        assert Path(root).stat().st_mode & 0o077 == 0
''')

    def test_platform_defaults_follow_platformdirs_and_xdg(self):
        self.scenario('''import os
from pathlib import Path
from platformdirs import user_config_dir,user_state_dir,user_data_dir
from argus import config
assert config.ARGUS_CONFIG_DIR == os.path.abspath(user_config_dir('argus',appauthor=False))
assert config.ARGUS_STATE_DIR == os.path.abspath(user_state_dir('argus',appauthor=False))
assert config.ARGUS_ASSET_DIR == os.path.abspath(user_data_dir('argus',appauthor=False))
if os.name == 'posix' and __import__('sys').platform != 'darwin':
    assert config.ARGUS_CONFIG_DIR == str(Path(os.environ['XDG_CONFIG_HOME'],'argus'))
    assert config.ARGUS_STATE_DIR == str(Path(os.environ['XDG_STATE_HOME'],'argus'))
    assert config.ARGUS_ASSET_DIR == str(Path(os.environ['XDG_DATA_HOME'],'argus'))
''', platform_paths=True)

    def test_defaults_are_usable_private_and_do_not_load_missing_files(self):
        self.scenario('''from pathlib import Path
from argus import config
settings=config.get_settings()
assert settings is config.get_settings()
assert settings['prompt'].format(cwd='/example') == 'Argus [/example] > '
assert settings['startup_files'] == []
assert settings['no_color'] is False and settings['accessibility'] is False
assert settings['locale'] == 'en'
assert settings['history_private'] is False
assert settings['history_limit'] == 1000 and settings['history_ignore'] == []
assert settings['redaction_patterns'] == []
assert settings['retention_records'] == 10000 and settings['retention_days'] == 0
assert settings['archive_encrypted'] is True
assert settings['audit_sign'] is False and settings['strict'] is False
assert settings['schema_version'] == 1
before=dict(settings)
assert config.load_settings() is False
assert settings == before
assert not Path(config.SETTINGS_FILE).exists()
settings['startup_files'].append('local-only')
assert config.DEFAULT_SETTINGS['startup_files'] == []
''')

    def test_settings_roundtrip_preserves_live_dictionary_and_nested_values(self):
        self.scenario('''import json,os
from pathlib import Path
from argus import config
config.prepare_paths()
live=config.get_settings()
source={'prompt':'[{cwd}] λ > ','startup_files':['startup file.argus'],
        'no_color':True,'accessibility':True,'locale':'fr',
        'history_private':True,'history_limit':17,'history_ignore':['^private '],
        'redaction_patterns':['customer-[0-9]+'],'retention_records':12,
        'retention_days':30,'archive_dir':str(Path(config.ARGUS_ASSET_DIR,'custom archives')),
        'archive_encrypted':False,'audit_sign':True,
        'audit_chain':str(Path(config.ARGUS_STATE_DIR,'custom.chain')),
        'broker_socket':'custom-endpoint','broker_public_key':'custom-public-key','strict':False}
assert config.save_settings(source)
assert live is config.get_settings()
for key,value in source.items(): assert live[key] == value, key
source['startup_files'].append('must-not-alias')
assert live['startup_files'] == ['startup file.argus']
saved=json.loads(Path(config.SETTINGS_FILE).read_text())
live['prompt']='temporary'
assert config.load_settings()
assert live is config.get_settings() and live == saved
assert config.DEFAULT_SETTINGS['startup_files'] == []
if os.name == 'posix': assert Path(config.SETTINGS_FILE).stat().st_mode & 0o077 == 0
''')

    def test_invalid_settings_never_replace_live_or_saved_settings(self):
        self.scenario('''import copy,json
from pathlib import Path
from argus import config
config.prepare_paths()
assert config.save_settings({'prompt':'kept {cwd}'})
live=config.get_settings()
expected=copy.deepcopy(live)
original=Path(config.SETTINGS_FILE).read_bytes()
invalid=[[],{'unrecognized':True},{'schema_version':2},{'schema_version':True},
         {'no_color':1},{'strict':'false'},{'history_limit':True},
         {'retention_records':-1},{'retention_days':10000001},
         {'startup_files':'not-a-list'},{'startup_files':[1]},
         {'history_ignore':['[']},{'redaction_patterns':['x'*4097]},
         {'locale':'nul\\0locale'},{'archive_dir':'relative'},{'audit_chain':'relative'}]
for candidate in invalid:
    try:
        config.save_settings(candidate)
    except (ValueError,TypeError,__import__('re').error):
        pass
    else:
        raise AssertionError('invalid settings accepted: '+repr(candidate))
    assert live is config.get_settings() and live == expected
    assert Path(config.SETTINGS_FILE).read_bytes() == original
bad=Path(config.ARGUS_CONFIG_DIR,'invalid.json')
from argus.storage import atomic_write
for content in ('{broken json',json.dumps({'no_color':'not boolean'})):
    atomic_write(bad,content)
    try:
        config.load_settings(bad)
    except ValueError:
        pass
    else:
        raise AssertionError('malformed settings loaded')
    assert live is config.get_settings() and live == expected
''')

    def test_custom_settings_file_does_not_change_default_location(self):
        self.scenario('''from pathlib import Path
from argus import config
config.prepare_paths()
custom=Path(config.ARGUS_CONFIG_DIR,'profiles','accessible.json')
assert config.save_settings({'accessibility':True,'no_color':True},path=custom)
assert custom.exists() and not Path(config.SETTINGS_FILE).exists()
config.get_settings()['accessibility']=False
assert config.load_settings(path=custom)
assert config.get_settings()['accessibility'] is True
assert config.SETTINGS_FILE == str(Path(config.ARGUS_CONFIG_DIR,'settings.json'))
''')

    def test_settings_never_serialize_environment_or_vault_secrets(self):
        self.scenario('''import json,os
from pathlib import Path
os.environ['API_TOKEN']='environment-secret-not-config'
os.environ['ARGUS_VAULT_PASSWORD']='vault-secret-not-config'
from argus import config
config.prepare_paths()
assert config.save_settings({'history_private':True})
content=Path(config.SETTINGS_FILE).read_text()
assert 'environment-secret-not-config' not in content
assert 'vault-secret-not-config' not in content
assert 'API_TOKEN' not in content and 'ARGUS_VAULT_PASSWORD' not in content
assert set(json.loads(content)) == set(config.DEFAULT_SETTINGS)
try:
    config.save_settings({'vault_password':'never-store-this-secret'})
except ValueError:
    pass
else:
    raise AssertionError('arbitrary secret field accepted')
assert 'never-store-this-secret' not in Path(config.SETTINGS_FILE).read_text()
''')

    def test_real_legacy_database_policy_and_history_migrate_once(self):
        self.scenario('''import json,os,sqlite3
from pathlib import Path
from contextlib import closing
home=Path.home()
legacy=home/'.argus'
legacy.mkdir(mode=0o700)
policy=legacy/'policy.json'
policy.write_text('{"mode":"monitor"}\\n')
policy.chmod(0o600)
history=home/'.argus_history'
history.write_text('printf legacy-one\\nprintf legacy-two\\n')
history.chmod(0o600)
old=legacy/'argus.db'
with closing(sqlite3.connect(old)) as connection, connection:
    connection.execute('CREATE TABLE legacy_records(id INTEGER PRIMARY KEY, command TEXT)')
    connection.execute("INSERT INTO legacy_records(command) VALUES('retained database row')")
old.chmod(0o600)
from argus import config
config.prepare_paths()
assert Path(config.ARGUS_POLICY_FILE).read_bytes() == policy.read_bytes()
assert Path(config.ARGUS_STATE_DIR,'legacy-history').read_bytes() == history.read_bytes()
with closing(sqlite3.connect(config.ARGUS_DATABASE)) as connection:
    assert connection.execute('SELECT command FROM legacy_records').fetchone()[0] == 'retained database row'
marker=Path(config.ARGUS_STATE_DIR,'migration.json')
content=marker.read_bytes()
assert set(json.loads(content)['imported']) == {str(policy),str(history),str(old)}
assert all(path.exists() for path in (policy,history,old))
policy.write_text('{"mode":"changed-legacy"}')
history.write_text('changed legacy history')
config.prepare_paths()
assert marker.read_bytes() == content
assert 'changed-legacy' not in Path(config.ARGUS_POLICY_FILE).read_text()
assert 'changed legacy history' not in Path(config.ARGUS_STATE_DIR,'legacy-history').read_text()
if os.name == 'posix':
    for path in (Path(config.ARGUS_POLICY_FILE),Path(config.ARGUS_DATABASE),Path(config.ARGUS_STATE_DIR,'legacy-history'),marker):
        assert path.stat().st_mode & 0o077 == 0, path
''')

    def test_migration_never_overwrites_existing_destinations(self):
        self.scenario('''import sqlite3
from pathlib import Path
from contextlib import closing
from argus import config
from argus.storage import private_directory,atomic_write,open_private
legacy=Path.home()/'.argus'
private_directory(legacy)
atomic_write(legacy/'policy.json','legacy-policy')
atomic_write(Path.home()/'.argus_history','legacy-history')
with closing(sqlite3.connect(legacy/'argus.db')) as connection, connection:
    connection.execute('CREATE TABLE old_data(value TEXT)')
(legacy/'argus.db').chmod(0o600)
for path in (config.ARGUS_CONFIG_DIR,config.ARGUS_STATE_DIR,config.ARGUS_ASSET_DIR): private_directory(path)
atomic_write(config.ARGUS_POLICY_FILE,'existing-policy')
atomic_write(Path(config.ARGUS_STATE_DIR,'legacy-history'),'existing-history')
fd=open_private(config.ARGUS_DATABASE)
__import__('os').close(fd)
with closing(sqlite3.connect(config.ARGUS_DATABASE)) as connection, connection:
    connection.execute('CREATE TABLE current_data(value TEXT)')
config.prepare_paths()
assert Path(config.ARGUS_POLICY_FILE).read_text() == 'existing-policy'
assert Path(config.ARGUS_STATE_DIR,'legacy-history').read_text() == 'existing-history'
with closing(sqlite3.connect(config.ARGUS_DATABASE)) as connection:
    assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [('current_data',)]
''')

    @unittest.skipUnless(os.name == 'posix', 'requires Unix symlink and permission boundaries')
    def test_migration_rejects_symlink_sources_without_marking_success(self):
        self.scenario('''from pathlib import Path
from argus import config
from argus.storage import private_directory,atomic_write
legacy=Path.home()/'.argus'
private_directory(legacy)
external=Path.home()/'outside-policy'
atomic_write(external,'outside policy')
(legacy/'policy.json').symlink_to(external)
try:
    config.prepare_paths()
except PermissionError:
    pass
else:
    raise AssertionError('symlink legacy policy accepted')
assert not Path(config.ARGUS_POLICY_FILE).exists()
assert not Path(config.ARGUS_STATE_DIR,'migration.json').exists()
assert external.read_text() == 'outside policy'
''')


if __name__ == '__main__':
    unittest.main()
