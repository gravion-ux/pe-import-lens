<p align="center"><img src="assets/banner.svg" alt="pe-import-lens banner" width="100%"/></p>

# PE Import Lens

[![CI](https://github.com/gravion-ux/pe-import-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/gravion-ux/pe-import-lens/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Dependency-free triage of Windows PE import tables.**

Built as a companion to WinAPI Sentinel: source-level review on one side,
binary-level import triage on the other.

## Usage

```bash
pip install -e .
pe-import-lens scan suspicious.exe
pe-import-lens scan suspicious.exe --json
```

Exit code is non-zero when a high-severity import is flagged.

## License

MIT
