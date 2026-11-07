"""Behavioural requirements for bounded state and resource path checking."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from eigen_state import scanner as checker


class StateAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def check(self, source, extension='py', **kwargs):
        path = self.root / ('sample.' + extension)
        path.write_text(source)
        report = checker.check_files(self.root, [path.name], **kwargs)
        self.assertEqual(report['mode'], 'state_checks')
        self.assertEqual(report['files'][0]['sha256'], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(path.read_text(), source)
        return report

    def entries(self, report, category):
        return [e for e in report['entries'] if e['category'] == category]

    def rules(self, report):
        return {e['rule'] for e in self.entries(report, 'finding')}

    def sources(self, py, js):
        return [('py', py), ('js', js), ('ts', js.replace('function run(flag)', 'function run(flag: boolean)'))]

    def test_leak_and_finally_repair_in_each_language(self):
        broken = self.sources('def run(flag):\n    f = open("x")\n    if flag:\n        return 1\n    f.close()\n',
                              'async function run(flag) { const f = await fs.open("x"); if (flag) return 1; await f.close(); }')
        fixed = self.sources('def run(flag):\n    f = open("x")\n    try:\n        if flag:\n            return 1\n    finally:\n        f.close()\n',
                             'async function run(flag) { const f = await fs.open("x"); try { if (flag) return 1; } finally { await f.close(); } }')
        for (ext, bad), (_, good) in zip(broken, fixed):
            with self.subTest(ext=ext):
                report = self.check(bad, ext)
                self.assertIn('resource-unreleased', self.rules(report))
                finding = next(e for e in self.entries(report, 'finding') if e['rule'] == 'resource-unreleased')
                self.assertTrue(finding['witness']); self.assertTrue(finding['assumptions'])
                self.assertNotIn('resource-unreleased', self.rules(self.check(good, ext)))

    def test_candidates_include_literal_states_and_guarded_transitions(self):
        for ext, source in self.sources('def run(flag):\n    state = "idle"\n    if flag:\n        state = "ready"\n    return state\n',
                                       'function run(flag) { let state = "idle"; if (flag) state = "ready"; return state; }'):
            with self.subTest(ext=ext):
                candidate = next(e for e in self.entries(self.check(source, ext), 'candidate') if e['owner'] == 'state')
                self.assertEqual(set(candidate['states']), {'idle', 'ready'})
                self.assertTrue(any(t['from'] == 'idle' and t['to'] == 'ready' and t['guards'] for t in candidate['transitions']))

    def test_guard_feasibility_and_simple_alias_release(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    other = f\n    done = False\n    if done:\n        return 1\n    other.close()\n',
                                       'async function run(flag) { const f = await fs.open("x"); const other = f; let done = false; if (done) return 1; await other.close(); }'):
            with self.subTest(ext=ext): self.assertNotIn('resource-unreleased', self.rules(self.check(source, ext)))

    def test_release_then_use_and_double_release(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    f.close()\n    f.read()\n    f.close()\n',
                                       'async function run(flag) { const f = await fs.open("x"); await f.close(); await f.read(); await f.close(); }'):
            with self.subTest(ext=ext):
                rules = self.rules(self.check(source, ext))
                self.assertIn('resource-use-after-release', rules)
                self.assertIn('resource-repeated-release', rules)

    def test_exceptional_exit_and_finally_override(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    risky()\n    f.close()\n',
                                       'async function run(flag) { const f = await fs.open("x"); risky(); await f.close(); }'):
            with self.subTest(ext=ext): self.assertIn('resource-unreleased', self.rules(self.check(source, ext)))
        for ext, source in self.sources('def run(flag):\n    try:\n        raise ValueError("primary")\n    finally:\n        cleanup()\n',
                                       'function run(flag) { try { throw new Error("primary"); } finally { cleanup(); } }'):
            with self.subTest(ext=ext): self.assertIn('cleanup-overrides-exit', self.rules(self.check(source, ext)))

    def test_catch_does_not_erase_normal_path_leak(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    try:\n        risky()\n    except Exception:\n        f.close()\n',
                                       'async function run(flag) { const f = await fs.open("x"); try { risky(); } catch (e) { await f.close(); } }'):
            with self.subTest(ext=ext): self.assertIn('resource-unreleased', self.rules(self.check(source, ext)))

    def test_unawaited_js_release_is_not_completed(self):
        for ext in ['js', 'ts']:
            result = self.check('async function run() { const f = await fs.open("x"); f.close(); }', ext)
            self.assertIn('resource-release-unawaited', self.rules(result))
            self.assertIn('resource-unreleased', self.rules(result))

    def test_return_resource_transfers_ownership(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    return f\n',
                                       'async function run(flag) { const f = await fs.open("x"); return f; }'):
            with self.subTest(ext=ext): self.assertNotIn('resource-unreleased', self.rules(self.check(source, ext)))

    def test_scopes_stay_separate_and_shadowing_is_a_gap(self):
        report = self.check('def first():\n    state = "one"\n    state = "two"\ndef second():\n    state = "three"\n    state = "four"\n')
        candidates = self.entries(report, 'candidate')
        self.assertEqual({e['scope'] for e in candidates}, {'first', 'second'})
        report = self.check('function run() { let state = "outer"; { let state = "inner"; state = "end"; } }', 'ts')
        self.assertTrue(any(e['rule'] == 'shadowed-binding' for e in self.entries(report, 'gap')))

    def test_unknown_operations_and_loops_are_explicit_gaps(self):
        for ext, source in self.sources('def run(flag):\n    resource = custom_acquire()\n    while flag:\n        custom_release(resource)\n',
                                       'function run(flag) { const resource = custom_acquire(); while (flag) { custom_release(resource); } }'):
            with self.subTest(ext=ext):
                report = self.check(source, ext)
                self.assertEqual(report['analysis_status'], 'partial')
                self.assertTrue(self.entries(report, 'gap'))

    def test_budgets_and_pagination_are_visible_and_stable(self):
        source = 'def run(flag):\n' + ''.join(f'    if flag{i}:\n        x = {i}\n' for i in range(12))
        report = self.check(source, max_paths=4, limit=200)
        self.assertTrue(any(e['rule'] == 'path-budget' for e in self.entries(report, 'gap')))
        first = self.check(source, max_paths=4, limit=1)
        entries = list(first['entries']); offset = first['next_offset']
        while offset is not None:
            page = self.check(source, max_paths=4, limit=1, offset=offset)
            entries.extend(page['entries']); offset = page['next_offset']
        self.assertEqual(entries, report['entries'])

    def test_same_named_methods_keep_distinct_machine_identity(self):
        report = self.check('class A { run() { let state = "a"; state = "b"; } }\nclass B { run() { let state = "c"; state = "d"; } }', 'ts')
        candidates = self.entries(report, 'candidate')
        self.assertEqual(len(candidates), 2)
        self.assertEqual(len({e['scope_id'] for e in candidates}), 2)

    def test_failed_finally_cancels_resource_return_transfer(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    try:\n        return f\n    finally:\n        cleanup()\n',
                                       'async function run(flag) { const f = await fs.open("x"); try { return f; } finally { cleanup(); } }'):
            with self.subTest(ext=ext): self.assertIn('resource-unreleased', self.rules(self.check(source, ext)))

    def test_returning_released_handle_is_reported(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    try:\n        return f\n    finally:\n        f.close()\n',
                                       'async function run(flag) { const f = await fs.open("x"); try { return f; } finally { await f.close(); } }'):
            with self.subTest(ext=ext): self.assertIn('resource-return-released', self.rules(self.check(source, ext)))

    def test_guard_repeated_and_negated_is_feasible(self):
        for ext, source in self.sources('def run(flag):\n    f = open("x")\n    if flag:\n        f.close()\n    if not flag:\n        f.close()\n',
                                       'async function run(flag) { const f = await fs.open("x"); if (flag) await f.close(); if (!flag) await f.close(); }'):
            with self.subTest(ext=ext):
                rules = self.rules(self.check(source, ext))
                self.assertNotIn('resource-unreleased', rules)
                self.assertNotIn('resource-repeated-release', rules)

    def test_js_loose_equality_is_not_python_equality(self):
        report = self.check('async function run() { const f = await fs.open("x"); if (1 == "1") return; await f.close(); }', 'js')
        self.assertIn('resource-unreleased', self.rules(report))

    def test_complexity_and_unsupported_input_terminate_with_gap(self):
        report = self.check('def run():\n    x = ' + 'not ' * 600 + 'True\n')
        self.assertEqual(report['analysis_status'], 'partial')
        for ext in ['tsx', 'jsx', 'mts', 'mjs']:
            report = self.check('async function run() { const f = await fs.open("x"); return 1; }', ext)
            self.assertIn('resource-unreleased', self.rules(report))

    def test_runtime_calibrates_early_return_and_finally_in_all_languages(self):
        py_prefix = 'owned = set()\nclass Handle:\n    def close(self): owned.discard(self)\ndef open(name):\n    h = Handle()\n    owned.add(h)\n    return h\n'
        js_prefix = 'const owned = new Set(); const fs = {async open(name) { const h = {async close() {owned.delete(h);}}; owned.add(h); return h; }};\n'
        for fixed in [False, True]:
            py = ('def run(flag):\n    f = open("x")\n    try:\n        return 1\n    finally:\n        f.close()\n' if fixed else
                  'def run(flag):\n    f = open("x")\n    return 1\n')
            js = ('async function run(flag) { const f = await fs.open("x"); try { return 1; } finally { await f.close(); } }' if fixed else
                  'async function run(flag) { const f = await fs.open("x"); return 1; }')
            for ext, source in self.sources(py, js):
                with self.subTest(ext=ext, fixed=fixed):
                    report = self.check(source, ext)
                    path = self.root / ('runtime.' + ext)
                    if ext == 'py':
                        path.write_text(py_prefix + source + '\nrun(True)\nprint(len(owned))\n')
                        command = [sys.executable, '-B', str(path)]
                    else:
                        path.write_text(js_prefix + source + '\nrun(true).then(() => console.log(owned.size));\n')
                        command = ['node', '--experimental-strip-types', str(path)]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), '0' if fixed else '1')
                    self.assertEqual('resource-unreleased' in self.rules(report), not fixed)

    def test_call_failure_edges_preserve_visible_trace_limit(self):
        source = 'def run():\n    f = open("x")\n' + ''.join(f'    x = {i}\n' for i in range(30)) + '    return 1\n'
        finding = next(e for e in self.entries(self.check(source), 'finding') if e['rule'] == 'resource-unreleased')
        self.assertTrue(finding['witness_truncated'])

    def test_caught_finally_error_preserves_primary_exception(self):
        for ext, source in self.sources('def run(flag):\n    try:\n        raise ValueError("primary")\n    finally:\n        try:\n            cleanup()\n        except:\n            pass\n',
                                       'function run(flag) { try { throw new Error("primary"); } finally { try { cleanup(); } catch (e) {} } }'):
            with self.subTest(ext=ext): self.assertNotIn('cleanup-overrides-exit', self.rules(self.check(source, ext)))

    def test_numeric_and_identity_guards_keep_language_semantics(self):
        report = self.check('async function run() { const f = await fs.open("x"); if (1 === 1.0) return; await f.close(); }', 'js')
        self.assertIn('resource-unreleased', self.rules(report))
        report = self.check('def run():\n    f = open("x")\n    if 1000 is 1000:\n        return\n    f.close()\n')
        self.assertTrue(any(e['rule'] == 'identity-comparison' for e in self.entries(report, 'gap')))

    def test_state_values_keep_boolean_and_numeric_identity(self):
        report = self.check('function run() { let state = false; state = 0; state = true; state = 1; }', 'js')
        candidate = self.entries(report, 'candidate')[0]
        self.assertEqual(len(candidate['states']), 4)

    def test_selected_sources_are_data_and_exclusions_apply_to_check_mode(self):
        marker = self.root / 'should-not-exist'
        self.check(f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\n')
        self.assertFalse(marker.exists())
        safe = self.root / 'sample.py'
        (self.root / 'alias.py').symlink_to(safe)
        for name in ['alias.py', '../outside.py', 'auth.py']:
            with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                checker.check_files(self.root, [name])

    def test_source_error_survives_directory_cleanup_failure(self):
        import os
        from unittest.mock import patch
        (self.root / 'sample.py').write_text('state = "ready"\n')
        primary = OSError('synthetic source failure')
        original_open, original_close = os.open, os.close

        def open_failure(path, *args, **kwargs):
            if str(path) == 'sample.py': raise primary
            return original_open(path, *args, **kwargs)

        def close_failure(descriptor):
            original_close(descriptor)
            raise OSError('synthetic cleanup failure')

        with patch.object(os, 'open', open_failure), patch.object(os, 'close', close_failure):
            with self.assertRaises(OSError) as caught:
                checker.read_script(self.root, Path('sample.py'))
        self.assertIs(caught.exception, primary)
        self.assertTrue(any('synthetic cleanup failure' in note for note in primary.__notes__))
        self.assertEqual(checker.check_files(self.root, ['sample.py'])['files'][0]['status'], 'parsed')

    def test_scope_and_output_caps_are_reported(self):
        report = self.check(''.join(f'def f{i}():\n    pass\n' for i in range(130)))
        self.assertTrue(any(e['rule'] == 'scope-budget' for e in self.entries(report, 'gap')))
        source = '\n'.join(f'x = [{i}]' for i in range(1100))
        report = self.check(source, limit=1, offset=999)
        self.assertEqual(report['entries_total'], 1000)
        self.assertTrue(any(e['rule'] == 'entry-budget' for e in self.entries(self.check(source, limit=200), 'gap')))

    def test_long_elif_chain_is_a_gap_instead_of_a_crash(self):
        source = 'def run():\n    if flag0:\n        pass\n' + ''.join(f'    elif flag{i}:\n        pass\n' for i in range(1, 1100))
        report = self.check(source)
        self.assertTrue(any(e['rule'] == 'branch-depth' for e in self.entries(report, 'gap')))

    def test_cli_check_preserves_database_and_reports_parse_gap(self):
        (self.root / 'sample.py').write_text('def run():\n    f = open("x")\n')
        database = self.root / 'unused.db'
        args = [sys.executable, '-B', '-m', 'eigen_state', '--root', str(self.root), 'sample.py']
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('resource-unreleased', self.rules(json.loads(result.stdout)))
        self.assertFalse(database.exists())
        report = self.check('def broken(\n')
        self.assertEqual(report['files'][0]['status'], 'parse_error')
        self.assertEqual(report['analysis_status'], 'partial')
        with self.assertRaises(ValueError): self.check('x = 1', max_paths=0)


if __name__ == '__main__':
    unittest.main()
