import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_gui_module_imports():
    import gui
    assert hasattr(gui, "MainApp")
    assert hasattr(gui, "main")
    assert hasattr(gui, "SingleRoundTab")
    assert hasattr(gui, "FullAESTab")
    assert hasattr(gui, "AvalancheTab")
    assert hasattr(gui, "KeyExpansionTab")
    assert hasattr(gui, "SBoxTab")


def test_normalize_hex():
    import gui
    assert gui.normalize_hex("00 11 22") == "001122"
    assert gui.normalize_hex("  FF  ") == "ff"


def test_is_valid_hex_block():
    import gui
    assert gui.is_valid_hex_block("0" * 32) is True
    assert gui.is_valid_hex_block("0" * 31) is False
    assert gui.is_valid_hex_block("g" + "0" * 31) is False
