"""Consumer tests of the interpreter, independent of an installed platform shell."""
import io
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from argus.expansion import Expander, ExpansionError, arithmetic
from argus.language import (
    Command, LanguageError, Redirection, ShellRuntime, ShellState,
    command_text, is_complete, parse, preview,
)


class LanguageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        environment = dict(os.environ, HOME=str(self.home),
                           XDG_CONFIG_HOME=str(self.home / 'config'),
                           XDG_STATE_HOME=str(self.home / 'state'),
                           XDG_DATA_HOME=str(self.home / 'data'),
                           ARGUS_CONFIG_HOME=str(self.home / 'argus-config'),
                           ARGUS_STATE_HOME=str(self.home / 'argus-state'),
                           ARGUS_DATA_HOME=str(self.home / 'argus-data'))
        patcher = patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        old_cwd = os.getcwd()
        self.addCleanup(os.chdir, old_cwd)
        os.chdir(self.home)
        self.output, self.errors, self.calls = io.StringIO(), io.StringIO(), []
        self.runtime = ShellRuntime(self.execute, stdout=self.output, stderr=self.errors)

    def execute(self, commands, background, runtime):
        """An embedding executor: all interpreter commands must cross this seam."""
        self.calls.append((commands, background))
        if background:
            runtime.state.last_background = 4321
            return 0
        if len(commands) > 1:
            # Pipeline process transport belongs to tests/test_processes.py;
            # these assertions inspect the complete stage representation.
            return 0
        command = commands[0]
        with runtime.assignment_scope(command.assignments) if command.argv else _nullcontext():
            if not command.argv: return 0
            argv = command.argv
            if argv[0] == 'emit':
                print('|'.join(argv[1:]), file=runtime.stdout)
                return 0
            if argv[0] == 'cd':
                os.chdir(argv[1]); return 0
            if argv[0] == 'fail': return int(argv[1]) if len(argv) > 1 else 1
            if argv[0] == 'record-env':
                print(json.dumps(runtime.state.environment(), sort_keys=True), file=runtime.stdout)
                return 0
            status = runtime.run_builtin(argv)
            return 127 if status is None else status

    def run_script(self, source, status=0):
        self.assertEqual(self.runtime.run(source, filename='example.argus'), status, self.errors.getvalue())
        return self.output.getvalue().splitlines()

    def test_lists_short_circuit_and_status(self):
        self.assertEqual(self.run_script('false && emit bad; true || emit bad; false || emit good; emit $?; fail 7', status=7), ['good', '0'])
        # Last script above intentionally finishes with failure.

    def test_lists_failure_is_reported(self):
        self.run_script('true && fail 7', status=7)
        self.assertEqual(self.runtime.state.last_status, 7)

    def test_if_elif_else_and_conditions_use_executor(self):
        lines = self.run_script('if false; then emit bad; elif true; then emit elif; else emit bad; fi; if false; then :; else emit else; fi')
        self.assertEqual(lines, ['elif', 'else'])
        executed = [command.argv[0] for commands, _ in self.calls for command in commands]
        self.assertEqual(executed.count('false'), 2)
        self.assertIn('true', executed)

    def test_for_while_until_break_continue(self):
        lines = self.run_script('for x in a b c; do if [[ $x == b ]]; then continue; fi; emit "$x"; done; i=0; while [[ $i -lt 3 ]]; do emit "$i"; i=$((i+1)); done; until [[ $i -eq 4 ]]; do i=$((i+1)); done; for z in x y; do break; emit bad; done; emit "$i"')
        self.assertEqual(lines, ['a', 'c', '0', '1', '2', '4'])

    def test_nested_loop_control_and_c_style_loop(self):
        lines = self.run_script('for a in 1 2; do for b in x y; do emit "$a$b"; break 2; done; done; for ((i=0;i<3;i++)); do emit "$i"; done')
        self.assertEqual(lines, ['1x', '0', '1', '2'])

    def test_case_patterns_and_fallthrough(self):
        self.assertEqual(self.run_script('x=alpha; case "$x" in z*) emit bad;; a*|b*) emit match;& *) emit after;; esac; case x in x) emit first;;& z) emit bad;; x) emit second;; esac'), ['match', 'after', 'first', 'second'])

    def test_function_local_scope_and_positional_restoration(self):
        lines = self.run_script('x=outer; set -- original; f(){ local x=inner; y=global; emit "$x" "$1" "$#"; return 9; emit bad; }; f argument; emit "$?" "$x" "$y" "$1"')
        self.assertEqual(lines, ['inner|argument|1', '9|outer|global|original'])
        self.assertIsInstance(self.runtime.state.functions['f'], str)
        snapshot = json.loads(json.dumps(self.runtime.state.snapshot()))
        other = ShellRuntime(self.execute, state=ShellState.from_snapshot(snapshot), stdout=self.output, stderr=self.errors)
        self.assertEqual(other.run('f worker'), 9)
        self.assertEqual(other.state.variables['x'], 'outer')

    def test_group_parent_scope_and_subshell_isolation(self):
        (self.home / 'child').mkdir()
        self.assertEqual(self.run_script('x=outer; { x=group; }; (x=subshell; export CHILD=yes; cd child; emit "$x"); emit "$x"'), ['subshell', 'group'])
        self.assertEqual(os.getcwd(), str(self.home))
        self.assertNotIn('CHILD', self.runtime.state.variables)

    def test_special_parameters_and_quoted_at(self):
        lines = self.run_script('set -- "one two" "" three; emit "$#" "$0" "$1" "${3}"; emit "$@"; emit "$*"; shift 2; emit "$1"; emit background & emit "$!"; fail 6; emit "$?" "$$"')
        self.assertEqual(lines[:5], ['3|argus|one two|three', 'one two||three', 'one two  three', 'three', '4321'])
        self.assertEqual(lines[5], f'6|{self.runtime.state.pid}')
        self.runtime.state.positional = []
        self.assertEqual(Expander(self.runtime).word('"$@"'), [])

    def test_source_return_and_script_arguments(self):
        (self.home / 'included.argus').write_text('local_result=$1; export INCLUDED=ok; return 4; emit bad\n')
        self.assertEqual(self.run_script('set -- parent; source ./included.argus child; emit "$?" "$local_result" "$1" "$INCLUDED"'), ['4|child|parent|ok'])
        self.assertIn('INCLUDED', self.runtime.state.exported)

    def test_assignment_export_prefix_and_unset(self):
        self.run_script('LOCAL=private; export PUBLIC=visible; PUBLIC=temporary PREFIX=child record-env; record-env; unset PUBLIC')
        environments = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertNotIn('LOCAL', environments[0])
        self.assertEqual(environments[0]['PUBLIC'], 'temporary')
        self.assertEqual(environments[0]['PREFIX'], 'child')
        self.assertEqual(environments[1]['PUBLIC'], 'visible')
        self.assertNotIn('PREFIX', environments[1])
        self.assertNotIn('PUBLIC', self.runtime.state.variables)

    def test_expansion_quote_provenance_braces_tilde_glob(self):
        for name in ('a.txt', 'b.txt'): (self.home / name).touch()
        lines = self.run_script('VALUE="one two"; emit $VALUE "$VALUE"; emit {a,b}{1..2} {03..01}; emit *.txt "*.txt"; emit ~/folder; emit "" $MISSING')
        self.assertEqual(lines, ['one|two|one two', 'a1|a2|b1|b2|03|02|01', 'a.txt|b.txt|*.txt', str(self.home / 'folder'), ''])

    def test_posix_parameter_default_alternate_length_and_removal(self):
        lines = self.run_script('x=abcabc; empty=; emit "${missing:-default}" "${empty-default}" "${empty:-default}" "${x:+present}" "${#x}"; emit "${x#a*c}" "${x##a*c}" "${x%a*c}" "${x%%a*c}"; emit "${made:=assigned}" "$made"')
        self.assertEqual(lines, ['default||default|present|6', 'abc||abc|', 'assigned|assigned'])
        self.run_script('emit "${absent:?required}"', status=2)
        self.assertIn('required', self.errors.getvalue())

    def test_arithmetic_is_not_python_execution(self):
        s = self.runtime.state
        self.assertEqual(arithmetic('i=2', s), 2)
        self.assertEqual(arithmetic('i++ + 3 * 2', s), 8)
        self.assertEqual(s.variables['i'], '3')
        self.assertEqual(arithmetic('i < 4 && 2 != 0', s), 1)
        self.assertEqual(arithmetic('0 ? 3 : 9', s), 9)
        self.assertEqual(arithmetic('0 && i++', s), 0)
        self.assertEqual(s.variables['i'], '3')
        self.assertEqual(arithmetic('1 || i++', s), 1)
        self.assertEqual(s.variables['i'], '3')
        self.assertEqual(arithmetic('a=1,b=2,a+b', s), 3)
        self.assertEqual(s.variables['a'], '1')
        self.assertEqual(arithmetic('!2 == 1', s), 0)
        self.assertEqual(arithmetic('16#ff + 010', s), 263)
        with self.assertRaises(ExpansionError): arithmetic('__import__("os").system("true")', s)

    def test_substitution_uses_executor_strips_newlines_and_isolates_state(self):
        lines = self.run_script('x=parent; emit "$(x=child; emit "$x"; emit "")"; emit "$x"; emit `emit backtick`')
        self.assertEqual(lines, ['child', 'parent', 'backtick'])
        assignments = [c.assignments for commands, _ in self.calls for c in commands]
        self.assertIn({'x': 'child'}, assignments)
        self.assertEqual(self.runtime.state.variables['x'], 'parent')

    def test_pipeline_background_and_compound_stage_representation(self):
        self.run_script('emit a |& emit b; { emit group; } | emit right; f(){ emit function; }; f &')
        pipeline = self.calls[0][0]
        self.assertEqual([c.argv for c in pipeline], [['emit', 'a'], ['emit', 'b']])
        self.assertEqual(pipeline[0].redirections[-1], Redirection(2, '>&', '1'))
        self.assertEqual(self.calls[1][0][0].argv[0], '__argus_eval__')
        self.assertTrue(self.calls[-1][1])

    def test_all_fd_redirections_and_order_are_preserved(self):
        self.run_script('emit x 3<>rw 2>&1 1>out 4<&0 5>&- 6>>append 7>|clobber &>both &>>all <<<"here text"')
        redirs = self.calls[-1][0][0].redirections
        self.assertEqual([(r.fd, r.operator, r.target) for r in redirs], [(3, '<>', 'rw'), (2, '>&', '1'), (1, '>', 'out'), (4, '<&', '0'), (5, '>&', '-'), (6, '>>', 'append'), (7, '>|', 'clobber'), (1, '&>', 'both'), (1, '&>>', 'all'), (0, '<<<', 'here text')])
        self.assertFalse((self.home / 'out').exists())

    def test_heredoc_expansion_quoted_delimiter_and_tab_stripping(self):
        self.run_script('x=value; emit <<EOF\n$x "literal quotes"\nEOF\nemit <<\'EOF\'\n$x\nEOF\nemit <<-EOF\n\t$x\n\tEOF\n')
        redirs = [c.redirections[0] for commands, _ in self.calls for c in commands if c.redirections]
        self.assertEqual([(r.target, r.expand) for r in redirs], [('value "literal quotes"\n', True), ('$x\n', False), ('value\n', True)])

    def test_heredoc_pipeline_and_arguments_after_delimiter(self):
        self.run_script('emit <<EOF extra | emit next\nbody\nEOF\n')
        commands = self.calls[-1][0]
        self.assertEqual([c.argv for c in commands], [['emit', 'extra'], ['emit', 'next']])
        self.assertEqual(commands[0].redirections[0].target, 'body\n')

    def test_read_umask_alias_directory_stack_and_type(self):
        self.runtime.stdin = io.StringIO(' first second third\nraw\\text\n')
        (self.home / 'nested').mkdir()
        mask = os.umask(0); os.umask(mask)
        self.addCleanup(os.umask, mask)
        lines = self.run_script('read a b; emit "$a" "$b"; read -r raw; emit "$raw"; umask 027; umask; alias hi="emit hello"; hi world; unalias hi; pushd nested; popd; type emit; command -v true', status=0)
        self.assertEqual(lines[:4], ['first|second third', 'raw\\text', '0027', 'hello|world'])
        self.assertEqual(os.getcwd(), str(self.home))
        self.assertEqual(lines[-1], 'true')

    def test_command_bypasses_functions_and_exec_requests_replace(self):
        captured = []
        self.runtime.execute_external = lambda args, replace=False: captured.append((args, replace)) or 3
        self.run_script('f(){ emit hidden; }; command f arg; exec tool argument', status=3)
        self.assertEqual(captured, [(['f', 'arg'], False), (['tool', 'argument'], True)])
        self.assertFalse(self.runtime.bypass_functions)
        self.assertFalse(self.runtime.exec_requested)

    def test_signal_trap_is_queued_and_runs_through_executor(self):
        self.run_script("trap 'emit trapped' INT")
        self.runtime.deliver_signal(signal.SIGINT)
        self.assertEqual(self.output.getvalue(), '')
        self.runtime.state.last_status = 9
        self.runtime.drain_traps()
        self.assertEqual(self.output.getvalue(), 'trapped\n')
        self.assertEqual(self.runtime.state.last_status, 9)

    def test_set_nounset_noglob_and_readonly(self):
        (self.home / 'a.txt').touch()
        self.assertEqual(self.run_script('set -f; emit *.txt; readonly value=locked; value=changed', status=2), ['*.txt'])
        self.assertEqual(self.runtime.state.variables['value'], 'locked')
        self.run_script('set -u; emit "$unknown"', status=2)
        self.assertIn('unbound variable', self.errors.getvalue())

    def test_readonly_prefix_rejects_native_pipeline_and_background_before_launch(self):
        marker = self.home / 'native-launched'
        launched = []
        def execute(commands, background, runtime):
            if any(c.argv and c.argv[0] == sys.executable for c in commands):
                launched.append((commands, background))
                self.assertEqual(len(commands), 1, 'rejected pipeline reached native launch')
                self.assertFalse(background, 'rejected background command reached native launch')
                command = commands[0]
                return subprocess.run(command.argv, cwd=self.home,
                                      env=runtime.state.environment(command.assignments),
                                      capture_output=True, text=True, timeout=10).returncode
            return self.execute(commands, background, runtime)
        self.runtime.executor = execute
        self.run_script('export MARKER=' + shlex.quote(str(marker)) + '; readonly LOCKED=old')
        program = 'import os; from pathlib import Path; Path(os.environ[\"MARKER\"]).write_text(os.environ.get(\"LOCKED\", \"unset\"))'
        native = shlex.join([sys.executable, '-c', program])
        self.run_script(native)
        self.assertTrue(marker.exists(), 'native baseline did not execute')
        marker.unlink()
        launched.clear()
        cases = (
            'LOCKED=new ' + native + ' > direct-output',
            native + ' > pipeline-output | LOCKED=new ' + native,
            'LOCKED=new ' + native + ' &',
            '> \"$(' + native + ')\" LOCKED=new ' + native,
        )
        for source in cases:
            with self.subTest(source=source):
                self.run_script(source, status=2)
                self.assertEqual(launched, [])
                self.assertFalse(marker.exists())
                self.assertEqual(self.runtime.state.variables['LOCKED'], 'old')
        self.assertFalse((self.home / 'direct-output').exists())
        self.assertFalse((self.home / 'pipeline-output').exists())

    def test_noexec_never_expands_or_mutates_later_source(self):
        self.run_script('set -n; emit "$(emit forbidden)"; f(){ :; }; for x in item; do :; done')
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('f', self.runtime.state.functions)
        self.assertNotIn('x', self.runtime.state.variables)
        self.assertEqual(self.output.getvalue(), '')
        self.run_script('emit "$(emit still-forbidden)"')
        self.assertEqual(len(self.calls), 1)

    def test_guarded_grammar_mutations_can_be_denied(self):
        attempted = []
        def deny(commands, background, runtime):
            attempted.extend(c.argv[0] for c in commands if c.argv)
            return 126
        self.runtime.executor = deny
        self.run_script('f(){ :; }', status=126)
        self.assertNotIn('f', self.runtime.state.functions)
        self.run_script('for x in item; do :; done', status=126)
        self.assertNotIn('x', self.runtime.state.variables)
        self.run_script('emit "$((x=9))"', status=2)
        self.assertNotIn('x', self.runtime.state.variables)
        self.run_script('emit "${x:=assigned}"', status=2)
        self.assertNotIn('x', self.runtime.state.variables)
        self.assertEqual(attempted, ['__argus_define__', '__argus_assign__', '__argus_arithmetic__', '__argus_assign__'])

    def test_debug_error_and_return_traps_dispatch_real_commands(self):
        self.run_script("trap 'emit debug' DEBUG; true")
        self.assertEqual(self.output.getvalue(), 'debug\n')
        self.runtime.state.traps.clear()
        self.output.seek(0); self.output.truncate()
        self.run_script("trap 'emit error' ERR; false", status=1)
        self.assertEqual(self.output.getvalue(), 'error\n')
        self.runtime.state.traps.clear()
        self.output.seek(0); self.output.truncate()
        self.run_script("trap 'emit returning' RETURN; f(){ :; }; f")
        self.assertEqual(self.output.getvalue(), 'returning\n')

    def test_quoted_patterns_and_empty_quote_after_split(self):
        lines = self.run_script('x=abc; case "$x" in "a*") emit bad;; "a"*) emit case;; esac; if [[ $x == "a"* ]]; then emit test; fi; VALUE="a "; emit $VALUE""')
        self.assertEqual(lines, ['case', 'test', 'a|'])

    def test_case_quoted_and_escaped_metacharacters_are_literal(self):
        source = r'''
            case foo in "*") emit bad;; *) emit star-fallback;; esac
            case "*" in "*") emit star-literal;; esac
            case x in \?) emit bad;; ?) emit question-fallback;; esac
            case "?" in \?) emit question-literal;; esac
            case a in \[ab\]) emit bad;; [ab]) emit bracket-fallback;; esac
            case "[ab]" in \[ab\]) emit bracket-literal;; esac
            pattern="*"
            case foo in "$pattern") emit bad;; $pattern) emit variable-active;; esac
            case "*" in "$pattern") emit variable-literal;; esac
        '''
        self.assertEqual(self.run_script(source), [
            'star-fallback', 'star-literal', 'question-fallback', 'question-literal',
            'bracket-fallback', 'bracket-literal', 'variable-active', 'variable-literal',
        ])

    def test_alias_substitution_runs_once_and_nested_case_substitution(self):
        self.assertEqual(self.run_script('alias hi="emit alias"; hi "$(emit once)"; emit "$(case x in x) emit nested;; esac)"'), ['alias|once', 'nested'])
        once = [c for commands, _ in self.calls for c in commands if c.argv == ['emit', 'once']]
        self.assertEqual(len(once), 1)

    def test_assignment_substitution_status_and_sequential_values(self):
        self.assertEqual(self.run_script('a=one b=$a; emit "$a" "$b"; x=$(false); emit "$?" "$x"'), ['one|one', '1|'])

    def test_preview_visits_all_branches_and_has_no_side_effects(self):
        before = self.runtime.state.snapshot()
        commands, uncertainty = preview('if true; then emit "$(emit secret)"; else emit other > forbidden; fi; f(){ emit function; }; emit "${new:=value}"', self.runtime.state)
        self.assertIn(['emit', 'other'], [c.argv for c in commands])
        self.assertIn(['emit', 'function'], [c.argv for c in commands])
        self.assertTrue(any('command substitution' in u for u in uncertainty))
        self.assertTrue(any('control flow' in u for u in uncertainty))
        self.assertTrue(any('parameter assignment' in u for u in uncertainty))
        self.assertEqual(self.runtime.state.snapshot(), before)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.home / 'forbidden').exists())

    def test_contextual_syntax_errors_precede_execution(self):
        self.run_script('emit before; if true; then', status=2)
        self.assertEqual(self.calls, [])
        self.assertIn('example.argus:1:', self.errors.getvalue())
        with self.assertRaisesRegex(LanguageError, 'unsupported syntax: process_substitution'):
            parse('emit <(emit forbidden)', filename='unsupported.argus')

    def test_multiline_completeness(self):
        for source in ('emit "open', 'if true; then', 'if true; then :; else', 'if true; then\nemit x', 'while true; do', 'for x in a; do\n:', 'case x in', 'emit x |', 'emit \\', 'emit <<EOF\nbody\n'):
            with self.subTest(source=source): self.assertFalse(is_complete(source))
        for source in ('emit "closed"', 'if true; then :; fi', 'emit <<EOF\nbody\nEOF\n', 'emit ; ;'):
            with self.subTest(source=source): self.assertTrue(is_complete(source))

    def test_canonical_command_text_is_unambiguous(self):
        text = command_text(Command(['emit', 'a b', '|'], {'X': '1 2'}, [Redirection(2, '>&', '1')]))
        self.assertEqual(text, "X='1 2' emit 'a b' '|' 2>& 1")


class _nullcontext:
    def __enter__(self): return self
    def __exit__(self, *args): return False


if __name__ == '__main__':
    unittest.main()
