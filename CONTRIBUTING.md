# Contributing to Nexus Gate

## Adding a tool to the classifier

1. Add the tool to `KNOWN_INFRASTRUCTURE` in `client/nexus_structural.py`:

```python
"mytool": (Flow.UNCHANGED, True, False, False, False, False),
#          flow           reads writes net_in net_out executes
```

2. If the tool has subcommands with different behavior, add overrides:

```python
SUBCOMMAND_OVERRIDES["mytool"] = {
    "read":  (Flow.UNCHANGED,   True,  False, False, False, False),
    "push":  (Flow.LEAKED,      True,  False, True,  True,  False),
}
```

3. If specific flags change behavior:

```python
FLAG_OVERRIDES["mytool"] = {
    "--upload":  (Flow.LEAKED,  True, False, True, True, False),
    "--dry-run": (Flow.UNCHANGED, True, False, False, False, False),
}
```

4. Run the verifier:

```bash
cd client
python nexus_trace_compress.py
```

5. Run the test suite:

```bash
python test_malicious.py
```

## Running tests

```bash
cd client
python -m pytest test_malicious.py -v    # attack patterns
python nexus_trace_compress.py           # table consistency
python nexus_structural.py               # built-in classifier tests
```

## Code style

- Python 3.8+ standard library only — zero external dependencies in client
- Dashboard server is also stdlib-only
- No bare `except:` clauses — every catch must be specific
- File operations use atomic write (temp + rename) and file locking

## Pull requests

- One feature per PR
- Include tests for new classifier rules
- Run the full test suite before submitting
- Update README if adding user-facing features
