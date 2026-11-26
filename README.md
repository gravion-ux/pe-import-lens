# PE Import Lens

Dependency-free triage of Windows PE import tables. PE Import Lens parses
PE32 and PE32+ import directories with nothing but the Python standard
library, lists every imported function, and flags imports associated with
process injection, process hollowing, keylogging, and anti-analysis
checks. The target file is only parsed, never executed.

Built as a companion to WinAPI Sentinel after passing Red Team Leaders'
Certified Offensive Windows API (COWA) exam: source-level review on one
side, binary-level import triage on the other.

## Usage

```bash
pip install -e .
pe-import-lens scan suspicious.exe
pe-import-lens scan suspicious.exe --json
```

Exit code is non-zero when a high-severity import is flagged.

## License

MIT
