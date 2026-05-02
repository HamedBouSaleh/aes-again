import sys
from pathlib import Path
import io
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_flask_app_import():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import importlib.util
    spec = importlib.util.spec_from_file_location("web_app", Path(__file__).resolve().parent.parent / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    assert app is not None
    assert app.name == "app" or "app" in app.name


def test_flask_client_routes():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.get("/")
    assert r.status_code == 200
    r = client.get("/single-round")
    assert r.status_code == 200
    r = client.get("/full-aes")
    assert r.status_code == 200
    r = client.get("/word-doc")
    assert r.status_code == 200
    assert b"File Encrypt / Decrypt" in r.data
    r = client.get("/avalanche")
    assert r.status_code == 200
    r = client.get("/key-expansion")
    assert r.status_code == 200
    r = client.get("/sbox")
    assert r.status_code == 200
    r = client.get("/coach")
    assert r.status_code == 200
    assert b"AES Coach" in r.data
    r = client.get("/api/random-key")
    assert r.status_code == 200
    data = r.get_json()
    assert "key" in data and len(data["key"]) == 32
    r = client.get("/api/random-block")
    assert r.status_code == 200
    data = r.get_json()
    assert "block" in data and len(data["block"]) == 32
    r = client.get("/api/self-test")
    assert r.status_code == 200
    data = r.get_json()
    assert "passed" in data
    assert data["passed"] is True


def test_flask_encrypt_post():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/full-aes", data={
        "key": "000102030405060708090a0b0c0d0e0f",
        "block": "00112233445566778899aabbccddeeff",
        "mode": "encrypt",
    })
    assert r.status_code == 200
    assert b"Ciphertext" in r.data or b"Plaintext" in r.data


def test_flask_coach_grades_final_answer_and_steps():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/coach", data={
        "practice_key": "2b7e151628aed2a6abf7158809cf4f3c",
        "practice_block": "3243f6a8885a308d313198a2e0370734",
        "practice_mode": "encrypt",
        "final_answer": "3925841d02dc09fbdc118597196a0b32",
        "round_answer_0": "193de3bea0f4e22b9ac68d2ae9f84808",
        "round_answer_1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    })
    assert r.status_code == 200
    assert b"Correct final answer" in r.data
    assert b"1/2 submitted checkpoints correct" in r.data
    assert b"Different from expected state" in r.data


def test_flask_avalanche_shows_statistics_graphs():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/avalanche", data={
        "key1": "000102030405060708090a0b0c0d0e0f",
        "block1": "00112233445566778899aabbccddeeff",
        "key2": "000102030405060708090a0b0c0d0e0f",
        "block2": "00112233445566778899aabbccddee00",
        "mode": "same_key",
    })
    assert r.status_code == 200
    assert b"Changed input bits" in r.data
    assert b"Mismatch trend" in r.data
    assert b"Mismatch by round" in r.data
    assert b"Final mismatch" in r.data


def test_flask_key_expansion_shows_word_formulas():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/key-expansion", data={
        "key": "000102030405060708090a0b0c0d0e0f",
    })
    assert r.status_code == 200
    assert b"Standard AES-128 key schedule formulas" in r.data
    assert b"RotWord" in r.data
    assert b"SubWord" in r.data
    assert b"Rcon" in r.data
    assert b"w[4]" in r.data


def test_flask_word_doc_encrypt_upload():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    docx_like = b"PK\x03\x04word/document.xml example text"
    r = client.post("/word-doc", data={
        "key": "000102030405060708090a0b0c0d0e0f",
        "mode": "encrypt",
        "document": (io.BytesIO(docx_like), "sample.docx"),
    }, content_type="multipart/form-data")
    assert r.status_code == 200
    assert b"Encrypted document" in r.data
    assert b"sample.docx.aesdoc" in r.data
    assert b"First 128 output bytes" not in r.data


def test_word_doc_file_encryption_roundtrip():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    key_b = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    original = b"PK\x03\x04docx package bytes with text, images, tables"
    encrypted = app_module.encrypt_file_bytes(original, key_b)
    assert encrypted != original
    assert encrypted.startswith(app_module.DOC_MAGIC)
    assert app_module.decrypt_file_bytes(encrypted, key_b) == original


def test_flask_short_hex_is_padded():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/full-aes", data={
        "key": "01",
        "block": "02",
        "mode": "encrypt",
    })
    assert r.status_code == 200
    assert b"01000000000000000000000000000000" in r.data
    assert b"02000000000000000000000000000000" in r.data


def test_flask_empty_input_has_specific_error():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/single-round", data={
        "key": "",
        "block": "00112233445566778899aabbccddeeff",
        "round": "1",
    })
    assert r.status_code == 200
    assert b"Key is required" in r.data


def test_flask_invalid_and_long_input_errors():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("web_app", root / "web" / "app.py")
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    app.config["TESTING"] = True
    client = app.test_client()

    r = client.post("/key-expansion", data={"key": "zz"})
    assert r.status_code == 200
    assert b"can only contain hex characters" in r.data

    r = client.post("/key-expansion", data={"key": "00" * 17})
    assert r.status_code == 200
    assert b"must be 32 hex characters or fewer" in r.data
