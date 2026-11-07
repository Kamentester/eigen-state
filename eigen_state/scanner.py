"""Read explicitly selected source files and report bounded abstract paths."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript

from . import analysis

MAX_SCRIPT_BYTES = 1024 * 1024
PRUNE = {'node_modules', '__pycache__', 'sessions', 'memory', 'secrets', 'auth', 'backups', 'cache', 'state', 'logs', 'vendor', 'dist', 'build', 'generated', 'upstream', 'repo', 'revisions', 'sources', 'evidence', 'outputs', 'output', 'data', 'live', 'install', 'npm', 'tmp'}
SENSITIVE = re.compile(r'^(?:auth|credentials?|secrets?)(?:[._-]|$)', re.I)
TYPESCRIPT = {'.ts', '.mts', '.cts'}
JAVASCRIPT = {'.js', '.mjs', '.cjs'}
TSX = {'.tsx', '.jsx'}
LANGUAGES = {
    'ts': Language(tree_sitter_typescript.language_typescript()),
    'tsx': Language(tree_sitter_typescript.language_tsx()),
    'python': Language(tree_sitter_python.language()),
    'javascript': Language(tree_sitter_javascript.language()),
}


def script_language(path: Path, raw: bytes) -> str | None:
    suffix = path.suffix.lower()
    if suffix == '.md': return 'markdown'
    if suffix == '.py': return 'python'
    if suffix in TYPESCRIPT: return 'ts'
    if suffix in JAVASCRIPT: return 'javascript'
    if suffix in TSX: return 'tsx'
    if suffix == '.sh': return 'bash'
    return shebang_language(raw) if not suffix else None


def shebang_language(prefix: bytes) -> str | None:
    first = prefix.split(b'\n', 1)[0].lower()
    if not first.startswith(b'#!'): return None
    if b'python' in first: return 'python'
    if re.search(rb'(?:^|/|\s)(?:ba|z|da|k)?sh(?:\s|$)', first): return 'bash'
    return None


def read_script(root: Path, relative: Path) -> bytes:
    """Open a bounded regular file through descriptor-relative, symlink-safe reads."""
    if os.name != 'posix':
        raise ValueError('Descriptor-relative source reading requires POSIX')
    if relative.is_absolute() or not relative.parts or any(part in {'.', '..'} or part.startswith('.') or part in PRUNE or SENSITIVE.match(part) for part in relative.parts):
        raise ValueError(f'Excluded script path: {relative}')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            previous, directory = directory, child
            os.close(previous)
        descriptor = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SCRIPT_BYTES:
                raise ValueError(f'Expected a regular script of at most 1 MiB: {relative}')
            raw = stream.read(MAX_SCRIPT_BYTES + 1)
            if len(raw) > MAX_SCRIPT_BYTES:
                raise ValueError(f'Script grew beyond 1 MiB: {relative}')
            raw.decode('utf-8')
            return raw
    finally:
        primary = sys.exception()
        try:
            os.close(directory)
        except OSError as cleanup:
            if primary is None:
                raise
            primary.add_note('Source directory cleanup failed: ' + str(cleanup))


def check_files(root: Path, paths: list[str], limit: int = 80, offset: int = 0, *, max_paths: int = 64) -> dict:
    """Analyse an explicit file selection without creating an index or running source."""
    if not paths or len(set(paths)) > 32 or not 1 <= limit <= 200 or offset < 0:
        raise ValueError('Select 1–32 scripts, a limit of 1–200, and a nonnegative offset')
    if not 1 <= max_paths <= 256:
        raise ValueError('max_paths must be between 1 and 256')
    root = Path(root).resolve(strict=True)
    selected = {Path(p).relative_to(root) if Path(p).is_absolute() else Path(p) for p in paths}
    files, entries = [], []
    for path in sorted(selected):
        raw = read_script(root, path)
        language = script_language(path, raw)
        row = {'path': path.as_posix(), 'sha256': hashlib.sha256(raw).hexdigest(),
               'language': language, 'status': 'unsupported'}
        if language in LANGUAGES:
            tree = Parser(LANGUAGES[language]).parse(raw)
            row['status'] = 'parse_error' if tree.root_node.has_error else 'parsed'
            if row['status'] == 'parsed':
                entries.extend({'path': path.as_posix(), **entry}
                               for entry in analysis.analyze(raw, tree.root_node, language, max_paths))
        files.append(row)
    for row in files:
        if row['status'] != 'parsed':
            entries.append({'category': 'gap', 'rule': row['status'], 'path': row['path'],
                            'scope': '<file>', 'detail': 'Source could not be analysed.'})
    counts = dict(Counter(entry['category'] for entry in entries))
    page = entries[offset:offset + limit]
    return {'mode': 'state_checks', 'files': files,
            'analysis_status': 'partial' if counts.get('gap') else 'bounded',
            'assumptions': analysis.ASSUMPTIONS, 'counts': counts,
            'entries': page, 'entries_total': len(entries), 'offset': offset,
            'next_offset': offset + len(page) if offset + len(page) < len(entries) else None,
            'truncated': len(page) < len(entries), 'max_paths': max_paths}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd(), help='Source root; defaults to the current directory')
    parser.add_argument('--limit', type=int, default=80, help='1–200 report entries per page')
    parser.add_argument('--offset', type=int, default=0, help='Entry offset; compare source hashes across pages')
    parser.add_argument('--max-paths', type=int, default=64, help='1–256 paths per scope')
    parser.add_argument('paths', nargs='+', help='Explicit source files beneath the root')
    args = parser.parse_args(argv)
    try:
        result = check_files(args.root, args.paths, args.limit, args.offset, max_paths=args.max_paths)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0
