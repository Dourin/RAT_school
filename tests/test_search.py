import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import agent


def test_search_found(tmp_path):
    filename = f"test_file_{uuid.uuid4().hex}.txt"
    file_path = tmp_path / filename
    file_path.write_text("sample")

    found_path = agent.search(filename)
    assert found_path == str(file_path)


def test_search_not_found():
    filename = f"nonexistent_{uuid.uuid4().hex}.txt"
    result = agent.search(filename)
    assert result == "ERROR_NF"
