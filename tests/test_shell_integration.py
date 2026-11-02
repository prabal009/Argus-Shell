"""Portable end-to-end CLI, language and persistence acceptance."""
import json,os,pathlib,sqlite3,subprocess,sys,tempfile,unittest
from contextlib import closing
REPO=pathlib.Path(__file__).resolve().parents[1]
class ShellIntegrationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
  self.env=dict(os.environ,HOME=str(self.root),ARGUS_CONFIG_HOME=str(self.root/'config'),ARGUS_STATE_HOME=str(self.root/'state'),ARGUS_DATA_HOME=str(self.root/'data'),PYTHONPATH=str(REPO),NO_COLOR='1')
 def run_shell(self,source,*args):
  return subprocess.run([sys.executable,'-m','argus','--norc','--no-color','-c',source,*args],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=30)
 def rows(self):
  with closing(sqlite3.connect(self.root/'state/argus.db')) as c:
   c.row_factory=sqlite3.Row;return [dict(r) for r in c.execute('select * from command_audit')]
 def test_lists_conditionals_and_loops(self):
  r=self.run_shell('false && echo bad; true || echo bad; for x in a b; do echo "$x"; done; if true; then echo yes; else echo bad; fi')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'a\nb\nyes\n')
 def test_functions_case_locals_and_positional(self):
  r=self.run_shell('f() { local x=inner; case "$1" in yes) echo "$x";; *) echo bad;; esac; }; x=outer; f yes; echo "$x:$0:$1:$#"','name','arg')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'inner\nouter:name:arg:1\n')
 def test_substitutions_and_expansions(self):
  (self.root/'a.txt').touch();(self.root/'b.txt').touch()
  r=self.run_shell('x="one two"; printf "<%s>\\n" $x; echo {a,b}; echo $((2+3)); echo "$(echo nested)"; echo *.txt')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'<one>\n<two>\na b\n5\nnested\na.txt b.txt\n')
 def test_variables_and_prefix_environment(self):
  import shlex
  py=shlex.quote(sys.executable)
  r=self.run_shell('x=local; export y=exported; X=prefix '+py+' -c '+shlex.quote('import os;print(os.getenv("x"),os.getenv("y"),os.getenv("X"))')+'; echo "${X-unset}"')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'None exported prefix\nunset\n')
 def test_builtin_pipeline_isolation_and_here_string(self):
  r=self.run_shell('x=parent; export x; echo pipeline | read x; echo "$x"; read value <<< hello; echo "$value"')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'parent\nhello\n')
 def test_redirection_restoration_and_heredoc(self):
  r=self.run_shell('pwd > location; read value <<EOF\nhello\nEOF\necho "$value"; echo visible')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'hello\nvisible\n');self.assertEqual((self.root/'location').read_text().strip(),str(self.root))
 def test_script_and_source(self):
  (self.root/'values').write_text('VALUE=sourced\n');(self.root/'script').write_text('source values; echo "$VALUE:$1"\n')
  r=subprocess.run([sys.executable,'-m','argus','--norc','script','argument'],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=20)
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'sourced:argument\n')
 def test_exit_status_and_audit_identity(self):
  r=self.run_shell('cd nonexistent; exit 7');self.assertEqual(r.returncode,7)
  self.assertTrue(any(row['command_name']=='cd' and row['exit_status'] for row in self.rows()))
  self.assertTrue(any(row['command_name']=='exit' and row['exit_status']==7 for row in self.rows()))
 def test_policy_save_load_and_denied_redirect(self):
  r=self.run_shell('security mode block; deny echo; security save; security load; echo forbidden > marker; exit 0')
  self.assertEqual(r.returncode,0,r.stderr);self.assertFalse((self.root/'marker').exists());self.assertTrue((self.root/'config/policy.json').exists())
 def test_pure_risk_no_subject_effect(self):
  r=self.run_shell('risk \'echo "$(echo bad > marker)"\'')
  self.assertEqual(r.returncode,0,r.stderr);self.assertFalse((self.root/'marker').exists())
 def test_job_wait_and_background_builtin(self):
  r=self.run_shell('echo background > result & wait; read value < result; echo "$value"')
  self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(r.stdout.endswith('background\n'))
 def test_aliases_directory_stack_and_traps(self):
  (self.root/'sub').mkdir()
  r=self.run_shell('alias hi="echo hello"; hi; pushd sub > /dev/null; popd > /dev/null; trap "echo leaving" EXIT; echo done') if os.name=='posix' else self.run_shell('alias hi="echo hello"; hi; trap "echo leaving" EXIT; echo done')
  self.assertEqual(r.returncode,0,r.stderr);self.assertIn('hello\n',r.stdout);self.assertTrue(r.stdout.endswith('done\nleaving\n'))
 def test_no_color_version_help(self):
  r=self.run_shell('help');self.assertNotIn('\x1b[',r.stdout)
  for flag in ('--help','--version'):
   p=subprocess.run([sys.executable,'-m','argus',flag],env=self.env,capture_output=True,text=True,timeout=10);self.assertEqual(p.returncode,0,p.stderr)
 def test_query_export_and_configurable_retention(self):
  r=self.run_shell('echo logged; audit --search logged --format json; settings set retention_records 10')
  self.assertEqual(r.returncode,0,r.stderr);self.assertIn('query_command',r.stdout);self.assertEqual(json.loads((self.root/'config/settings.json').read_text())['retention_records'],10)
 def test_strict_missing_service_fails_closed(self):
  r=subprocess.run([sys.executable,'-m','argus','--norc','--strict','--broker',str(self.root/'absent.sock'),'-c','echo unsafe > marker'],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=10)
  self.assertEqual(r.returncode,126);self.assertFalse((self.root/'marker').exists())
 @unittest.skipUnless(os.name=='posix','POSIX executable and descriptor semantics')
 def test_exec_uses_unexported_shell_path(self):
  import shlex
  directory=self.root/'tools';directory.mkdir()
  tool=directory/'custom-tool';tool.write_text('#!'+sys.executable+'\nprint(\"custom-identity\")\n');tool.chmod(0o700)
  r=self.run_shell('export -n PATH; PATH='+shlex.quote(str(directory))+'; exec custom-tool')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'custom-identity\n')
 def test_persistent_exec_respects_noclobber(self):
  (self.root/'existing').write_text('keep')
  r=self.run_shell('set -C; exec >existing; echo visible')
  self.assertEqual((self.root/'existing').read_text(),'keep');self.assertIn('visible',r.stdout)
 def test_persistent_exec_discards_old_stdin_buffer(self):
  (self.root/'other').write_text('fresh\n')
  r=subprocess.run([sys.executable,'-m','argus','--norc','-c','read first; exec <other; read next; echo \"$next\"'],input='first\nstale\n',cwd=self.root,env=self.env,capture_output=True,text=True,timeout=20)
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'fresh\n')
 def test_wait_next_ignores_foreground_and_consumed_results(self):
  import shlex
  python=shlex.quote(sys.executable)
  r=self.run_shell(python+' -c \"raise SystemExit(7)\"; '+python+' -c \"import time; time.sleep(0.1)\" & wait -n; echo \"$?\"; wait -n; echo \"$?\"')
  self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(r.stdout.endswith('0\n127\n'),r.stdout)
 def test_subshell_exit_traps_are_not_lost(self):
  r=self.run_shell('(trap \"echo cleanup\" EXIT; echo body); echo parent')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'body\ncleanup\nparent\n')
if __name__=='__main__':unittest.main()
