# Benign tests to ensure arctest does not alert on 
# valid unit tests

import math
import json
from collections import defaultdict


def test_math_operations():
    assert math.sqrt(16) == 4
    assert math.pow(2, 3) == 8
    assert abs(-5) == 5


def test_string_manipulation():
    text = "hello world"
    assert text.upper() == "HELLO WORLD"
    assert text.split() == ["hello", "world"]
    assert "world" in text


def test_data_structures():
    data = {"key": "value", "numbers": [1, 2, 3]}
    assert data["key"] == "value"
    assert len(data["numbers"]) == 3

    counter = defaultdict(int)
    counter["a"] += 1
    counter["a"] += 1
    assert counter["a"] == 2


def test_json_parsing():
    json_str = '{"name": "test", "value": 42}'
    parsed = json.loads(json_str)
    assert parsed["name"] == "test"
    assert parsed["value"] == 42

    serialized = json.dumps(parsed)
    assert "test" in serialized


def test_list_comprehensions():
    squares = [x**2 for x in range(5)]
    assert squares == [0, 1, 4, 9, 16]

    evens = [x for x in range(10) if x % 2 == 0]
    assert evens == [0, 2, 4, 6, 8]
