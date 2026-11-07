# eigen-state

A bounded static checker for local state transitions and file-handle lifecycles in Python, JavaScript, and TypeScript. It reports potential defects with source locations, witness paths, assumptions, and coverage gaps. Selected source is parsed as data; analysis runs locally.

## Install and use

Use Python 3.12 on a POSIX system. Install the supplied wheel into a virtual environment:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install ./eigen_state-0.1.0-py3-none-any.whl
.venv/bin/eigen-state --root ./project sample.py
```

The module form is `python -m eigen_state --root ./project sample.py`. Select files explicitly. Paths stay beneath the chosen root; symlinks, hidden paths, sensitive filenames, and common generated/state directories are excluded. The tool creates its report on stdout and preserves source files.

Exit 0 means a report was produced. Exit 2 indicates invalid arguments or an input error. Inspect `counts`, `entries`, `analysis_status`, and each file’s status to evaluate the result. A report with findings still exits 0.

## Example: ownership on an early return

```python
def read_header(skip):
    handle = open("sample.txt")
    if skip:
        return "skipped"
    handle.close()
```

On the `skip` path, the return leaves an owned handle unreleased. The checker reports `resource-unreleased` with a branch guard and witness. A supported repair releases the handle through `finally`:

```python
def read_header(skip):
    handle = open("sample.txt")
    try:
        if skip:
            return "skipped"
    finally:
        handle.close()
```

The repair covers the early-return path. A failed close still produces an explicit release-outcome gap. Idiomatic context managers remain a review gap in this initial subset.

The synthetic tests contain corresponding Python, JavaScript, and TypeScript cases, including runtime-calibrated broken/repaired examples:

```sh
python -m unittest discover -s tests -v
```

Node is required for the JavaScript and TypeScript runtime fixtures; it must support `--experimental-strip-types`.

## Mechanism and limits

Tree-sitter parses source into language-specific syntax trees. The language adapter lowers supported statements into shared operations. A bounded abstract interpreter follows branch guards, literal values, local aliases, returns, exceptions, cleanup, and resource ownership. Literal assignments can expose candidate state machines; application contracts establish valid transitions.

Current handle summaries recognise Python `open` and awaited JavaScript `fs.open`/`fs.promises.open`, followed by handle methods and `close`. These names are API assumptions; aliases and shadowed APIs need source review. Rules cover unreleased handles, use after release, repeated release, unawaited close, returning released handles, and cleanup overriding pending exits.

Analysis is intraprocedural. Unknown calls, arbitrary expressions, loops, context managers, closures, cross-function identity, and concurrency have explicit coverage gaps. Unknown conditions branch both ways. Typed Python exception handlers are overapproximated. `partial` means gaps exist; `bounded` describes the supported abstraction.

Limits are 32 selected files, 1 MiB per file, 128 function scopes, 10,000 operation steps per file, 1,000 entries per file, and 64 active paths by default. `--max-paths` accepts 1–256. Use `--limit` 1–200 and the returned `next_offset` for paging. Each page rereads sources; compare file hashes before combining pages. Budget and witness truncation are reported.

Reports include selected filenames, symbol names, conditions, and source-derived values. Review a report’s contents before sharing it.

## Build and licence

From the source distribution, build with a PEP 517 frontend and the declared setuptools backend. The [MIT licence](LICENSE) covers this project. [Dependency notices](NOTICE) describe the separately distributed Tree-sitter components.
