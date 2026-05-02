# EECE 455/632 Project 7 — AES Again

AES-128 educational toolkit: **desktop GUI**, **Flask web app**, **full test suite**, and documentation.

**For reviewers and clients**

- **[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md)** — Architecture, modules, and how tests verify correctness.
- **[docs/CLIENT_DELIVERY.md](docs/CLIENT_DELIVERY.md)** — Handoff checklist: install, run, verify tests, what to zip.

## Quick start

**Desktop GUI (tkinter):**
```bash
python3 gui.py
```

**Flask web app:**
```bash
pip install flask
python3 web/app.py

for me (3.14.4)
python -m pip install flask
python web/app.py
```
Then open http://127.0.0.1:5000

**Run all tests:**
```bash
pip install pytest
python3 tests/run_all_tests.py
```
Or: `python3 -m pytest tests/ -v`

## Requirements

- **Python 3.10+**
- **GUI:** stdlib only (`tkinter`).
- **Web:** `flask>=3.0.0`
- **Tests:** `pytest>=7.0.0`

Install: `pip install -r requirements.txt`

---

## Desktop GUI (`gui.py`)

Single window with 5 tabs:

| Tab | Description |
|-----|-------------|
| **1. Single round** | Key + block + round (0–10). Load round → step through SubBytes, ShiftRows, MixColumns, AddRoundKey. Previous/Next. |
| **2. Full AES** | Encrypt or decrypt one block; state after each round. Random key/block, Load/Save file, Copy/Export output. |
| **3. Avalanche** | Same key + two blocks, or same block + two keys. Bit mismatch per round (0–128). Copy/Export. |
| **4. Key expansion** | 128-bit key → 44 words in 11 groups of 4. Random, Copy, Export. |
| **5. S-box / Rcon** | 16×16 S-box, inverse S-box, Rcon constants. |

**Extra:** Dark theme (View menu), tooltips, hex validation (✓), keyboard shortcuts (Ctrl+Enter, Ctrl+C), self-test (NIST), About/Help.

---

## Flask web app (`web/app.py`)

Same features in a browser:

- **Home** — Links to all tools.
- **Single round** — Form: key, block, round → load round → show all steps.
- **Full AES** — Encrypt or decrypt; state after each round. Random key/block buttons.
- **Avalanche** — Same key/different block or same block/different key; table of bit mismatch per round.
- **Key expansion** — Key → 11 round keys (4 words each). Random key button.
- **S-box / Rcon** — Tabs: S-box, inverse S-box, Rcon list.

**API (JSON):**

- `GET /api/random-key` → `{"key": "..."}`
- `GET /api/random-block` → `{"block": "..."}`
- `GET /api/self-test` → `{"passed": true, "message": "..."}`

---

## Tests

| Location | Description |
|----------|-------------|
| `tests/test_aes_core.py` | Parsing, state, key expansion, encrypt/decrypt, round steps, bit_mismatch. |
| `tests/test_nist_vectors.py` | NIST FIPS 197 Appendix C.1 + zero-key round-trip. |
| `tests/test_parsing.py` | Hex parsing (length, invalid chars, spaces). |
| `tests/test_key_expansion_detail.py` | First words from key, 11 round keys, hex format. |
| `tests/test_encrypt_decrypt_roundtrip.py` | Round-trip and round-by-round state. |
| `tests/test_avalanche.py` | Bit mismatch, same key/block vs different. |
| `tests/test_one_round_steps.py` | Step names and 4×4 state per step. |
| `tests/test_gui_import.py` | GUI module import and hex helpers. |
| `tests/test_flask_app.py` | Flask routes and encrypt POST. |

**Run everything and see pass/fail:**

```bash
python3 tests/run_all_tests.py
```

Reports which tests failed if any.

---

## Project 7 requirements

1. **Single-round step-by-step** — GUI and web: one round, pause after each step (SubBytes, ShiftRows, MixColumns, AddRoundKey).
2. **Full AES** — Encrypt or decrypt one block; show state after each round.
3. **Avalanche** — Two encryptions; report bit mismatch per round (same key/different block or same block/different key).
4. **Key expansion** — 128-bit key → 44 words in 11 groups of 4.

---

## Input format

- **Key / Block:** 32 hexadecimal characters (128 bits). Example: `000102030405060708090a0b0c0d0e0f`. Spaces/newlines ignored.

---

## Project layout

```
EECE 455 AES(Project 7)/
├── aes_core.py           # AES-128 core (no deps)
├── gui.py                # Desktop GUI (tkinter)
├── requirements.txt
├── pytest.ini
├── README.md
├── docs/
│   ├── HOW_IT_WORKS.md    # Full technical explanation
│   ├── CLIENT_DELIVERY.md # Handoff / submission checklist
│   └── PROJECT_PLAN.md    # Week-by-week plan
├── web/
│   ├── app.py            # Flask app
│   ├── templates/        # HTML (base, index, single_round, full_aes, avalanche, key_expansion, sbox)
│   └── static/
└── tests/
    ├── run_all_tests.py  # Run all tests and report
    ├── test_aes_core.py
    ├── test_nist_vectors.py
    ├── test_parsing.py
    ├── test_key_expansion_detail.py
    ├── test_encrypt_decrypt_roundtrip.py
    ├── test_avalanche.py
    ├── test_one_round_steps.py
    ├── test_gui_import.py
    └── test_flask_app.py
```