# EECE 455 Project 7 — AES Again: Week-by-Week Plan

## Overview

| Phase | Weeks | Focus |
|-------|--------|--------|
| **1. Core & spec** | 1–2 | AES-128 implementation, NIST validation, project spec |
| **2. GUI & UX** | 3–4 | Professional GUI, themes, validation, tooltips |
| **3. Features & polish** | 5–6 | Extra features, file I/O, export, S-box viewer |
| **4. Testing & docs** | 7–8 | Full test suite, README, demo prep |

---

## Week 1 — Specification & AES core

**Goals**

- Lock down Project 7 requirements (single-round step-by-step, full encrypt/decrypt, avalanche, key expansion).
- Implement AES-128 in pure Python: S-box, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey.
- Validate against at least one NIST known-answer test vector.

**Tasks**

- [ ] Read FIPS 197 and project handout; list all deliverables.
- [ ] Implement `aes_core.py`: state representation, S-box/InvSbox, Rcon, GF(2⁸) multiplication.
- [ ] Implement key expansion (128-bit → 44 words, 11 round keys).
- [ ] Implement encrypt/decrypt for one block; helper to return state after each round.
- [ ] Implement single-round step-by-step (SubBytes → ShiftRows → MixColumns → AddRoundKey) for rounds 1–9; round 10 without MixColumns.
- [ ] Add NIST test vector (e.g. Appendix C.1) and verify ciphertext/plaintext round-trip.

**Deliverables**

- `aes_core.py` with no external crypto libraries.
- One passing NIST vector check (manual or script).

---

## Week 2 — Core helpers & avalanche

**Goals**

- Expose round-by-round states and bit-mismatch for avalanche.
- Implement “crack”/analysis helpers (e.g. avalanche count per round).
- Keep core testable and easy to hook into a GUI.

**Tasks**

- [ ] Add `encrypt_block_with_rounds()` and `decrypt_block_with_rounds()` returning list of 11 states.
- [ ] Add `one_round_steps()` for step-by-step view (initial state + each op).
- [ ] Add `bit_mismatch(state_a, state_b)` for avalanche (bit differences per round).
- [ ] Add `words_to_hex_words()` for key schedule display (44 words in 11 groups of 4).
- [ ] Parse/validate hex key and block (32 hex chars); clear errors for GUI.
- [ ] Optional: add more NIST vectors (multiple keys/blocks) in a test file.

**Deliverables**

- All core APIs needed by the GUI.
- Avalanche logic ready (same key / different block and same block / different key).

---

## Week 3 — Basic GUI & single-round tab

**Goals**

- Working window with tabs.
- Single-round step-by-step: key, block, round selector, “Next step” with state matrix.
- Clean layout and basic styling.

**Tasks**

- [ ] Create main window (tkinter/ttk or CustomTkinter); notebook with tabs.
- [ ] Tab 1: inputs (key, block, round 0–10), “Load round”, “Next step”, “Reset”.
- [ ] Display 4×4 state matrix (hex bytes) after each step; label current step name.
- [ ] Input validation: show error dialog for invalid hex or round.
- [ ] Set a consistent font (e.g. Consolas) for hex and state grid.
- [ ] Optional: dark/light theme toggle and save preference.

**Deliverables**

- Runnable GUI with single-round step-by-step working end-to-end.

---

## Week 4 — Full AES tab & key expansion tab

**Goals**

- Tab 2: Full AES encrypt/decrypt with state after each round.
- Tab 4: Key expansion (44 words in groups of 4).
- Improve UX: status bar, copy button, clear buttons.

**Tasks**

- [ ] Tab 2: Encrypt / Decrypt buttons; output pane showing state after each round (0–10) and final block (hex).
- [ ] Tab 4: Key input → “Generate key schedule” → display 11 groups of 4 words (hex).
- [ ] Add status bar: “Ready”, “Encrypted”, “Invalid key”, etc.
- [ ] “Copy output” button for each output pane (copy to clipboard).
- [ ] “Clear” for inputs/outputs where useful.

**Deliverables**

- Full AES and Key Expansion tabs fully functional; status bar and copy.

---

## Week 5 — Avalanche tab & validation UX

**Goals**

- Tab 3: Avalanche — same key/different block and same block/different key; table of bit mismatch per round.
- Input validation with visual feedback (e.g. red/green border or icon).
- Tooltips and help text for key/block format.

**Tasks**

- [ ] Tab 3: Two modes (same key / same block); inputs for key(s) and block(s); “Run Avalanche” → table: round index vs. bit mismatch (0–128).
- [ ] Validate all hex fields; show inline error (e.g. “Invalid: need 32 hex chars”) and disable Run until valid.
- [ ] Add tooltips: “Key: 32 hex chars (128 bits)”; “Block: 32 hex chars (128 bits)”.
- [ ] Optional: byte/bit count under each hex field.

**Deliverables**

- Avalanche tab complete; validation and tooltips in place.

---

## Week 6 — Pro features (file I/O, random, export)

**Goals**

- Load/save key and block from/to files.
- Random key and random block buttons.
- Export report (e.g. full AES or avalanche results to .txt/.md).
- Keyboard shortcuts.

**Tasks**

- [ ] “Load key from file” / “Save key to file” (raw hex or one hex string per line).
- [ ] “Load block from file” / “Save block to file”.
- [ ] “Random key” / “Random block” (os.urandom(16) or secrets.token_hex(16)).
- [ ] “Export report”: current tab output to file (timestamped name or dialog).
- [ ] Shortcuts: e.g. Ctrl+Enter = Run/Encrypt/Generate, Ctrl+L = Load round, Ctrl+C = Copy output.
- [ ] About dialog: project title, course, FIPS 197 reference.

**Deliverables**

- File I/O, random key/block, export, shortcuts, About.

---

## Week 7 — S-box viewer & diagnostics

**Goals**

- Extra tab or dialog: S-box and Inverse S-box viewer (16×16 grid).
- Optional: Rcon list, mini “diagnostics” (e.g. one encrypt/decrypt round-trip to confirm core).

**Tasks**

- [ ] New tab or dialog: “S-box / Rcon viewer”.
- [ ] Display S-box and InvSbox as 16×16 hex grids (row = high nibble, col = low nibble).
- [ ] Display Rcon[i] for i = 0..10.
- [ ] Optional: “Run self-test” button that runs NIST vector and shows Pass/Fail in status bar.

**Deliverables**

- S-box/Rcon viewer; optional self-test in GUI.

---

## Week 8 — Testing, docs & demo prep

**Goals**

- Full test suite (pytest): core logic and NIST vectors.
- README and project plan (this document) finalized.
- Short demo script or checklist for presentation.

**Tasks**

- [ ] `tests/test_aes_core.py`: parse_hex_block/key, key_expansion, encrypt_block, decrypt_block, round-trip, bit_mismatch, one_round_steps, state_to_hex_grid.
- [ ] `tests/test_nist_vectors.py`: multiple NIST known-answer tests (Appendix C).
- [ ] `README.md`: run instructions, requirements, feature list, input format.
- [ ] Optional: `tests/test_gui.py` — minimal smoke test (import, create root, create notebook, destroy).
- [ ] Demo checklist: 1) Single round step-through, 2) Full encrypt/decrypt, 3) Avalanche (both modes), 4) Key expansion, 5) Export report, 6) S-box viewer.

**Deliverables**

- All tests passing; README and PROJECT_PLAN.md complete; demo checklist ready.

---

## Feature checklist (summary)

| Feature | Description |
|--------|--------------|
| Single-round step-by-step | Key + block + round → step through SubBytes, ShiftRows, MixColumns, AddRoundKey |
| Full AES encrypt/decrypt | State after each round (0–10); hex input/output |
| Avalanche | Same key/different block; same block/different key; bit mismatch per round |
| Key expansion | 128-bit key → 44 words in 11 groups of 4 |
| Pro GUI | Theme (light/dark), tooltips, status bar, validation feedback |
| Random key/block | One-click fill with cryptographically random key/block |
| File I/O | Load/save key and block (hex files) |
| Export report | Save current output to .txt or .md |
| Copy to clipboard | Copy output pane content |
| S-box / Rcon viewer | 16×16 S-box and InvSbox; Rcon list |
| Keyboard shortcuts | Ctrl+Enter, Ctrl+C, etc. |
| About / Help | Dialog with project and reference info |
| Testing | pytest; NIST vectors; core unit tests |

---

## Notes

- **Dependencies:** Keep core (aes_core.py) dependency-free; GUI can use only stdlib (tkinter) or optional CustomTkinter.
- **Python:** Target 3.10+ for type hints and clarity.
- **Revision control:** Commit at end of each week (or per task) with clear messages.
