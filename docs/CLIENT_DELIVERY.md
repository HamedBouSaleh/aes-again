# Client Delivery Package — AES Again (Project 7)

Use this checklist when **handing off the final project** to a client, instructor, or stakeholder.

---

## What is delivered

A single project folder containing:

- **Runnable desktop app** — *gui.py* (Python 3.10+, tkinter).
- **Runnable web app** — *web/app.py* (Flask).
- **AES-128 implementation** — *aes_core.py* (no external crypto dependencies).
- **Automated tests** — *tests/* (60 tests via pytest).
- **Documentation** — *README.md*, *docs/HOW_IT_WORKS.md*, *docs/CLIENT_DELIVERY.md*, *docs/PROJECT_PLAN.md*. (Add any course-required write-up separately, e.g. PDF or Word, if applicable.)

Optional: include a **demo video** if required; large media may be linked instead of embedded in the zip.

---

## Client environment

| Requirement | Notes |
|-------------|--------|
| Python | 3.10 or newer |
| Desktop GUI | Tkinter is included with most Python installs. |
| Web app | `pip install -r requirements.txt` (Flask). |
| Tests | Same *requirements.txt* includes pytest. |

---

## Installation

```bash
cd "<path-to-project-folder>"
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## How to run

| Component | Command |
|-----------|---------|
| Desktop | `python3 gui.py` |
| Web | `python3 web/app.py` then open http://127.0.0.1:5000 |
| Verify | `python3 tests/run_all_tests.py` → expect **60 passed** |

---

## Input rules

- Key and each block: **32** hexadecimal digits (128 bits).
- Spaces and newlines are ignored.

---

## Scope

**Included:** Single-block AES-128 (FIPS 197), single-round stepping, full encrypt/decrypt with per-round state, avalanche (two modes), key expansion (44 words / 11 groups of 4), S-box viewer, NIST self-test.

**Not included:** AES-192/256, CBC/GCM or other modes, padding, bulk file encryption.

---

## Suggested zip contents

Include the project root with *aes_core.py*, *gui.py*, *README.md*, *requirements.txt*, *pytest.ini*, *docs/*, *web/*, *tests/*. **Exclude** `.venv`, `__pycache__`, `.pytest_cache` when possible.

---

## Documentation map

| File | Purpose |
|------|---------|
| *README.md* | Quick start and feature list |
| *docs/HOW_IT_WORKS.md* | Technical deep dive |
| *docs/CLIENT_DELIVERY.md* | This handoff sheet |
| *docs/PROJECT_PLAN.md* | Planning artifact |
