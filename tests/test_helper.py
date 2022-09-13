### test helper functions
from nmap_scanner.helpers import helper

def test_validate_hostname():
    assert helper.validate_hostname("localhost")
    assert helper.validate_hostname("google.com")
    assert helper.validate_hostname("google.com.")

    assert not helper.validate_hostname("google.com-")
    assert not helper.validate_hostname("google..com-")

def test_compare_old_new():
    old = {}
    new = {1, 2}

    added, deleted = helper.compare_old_new(old , new)
    assert added == [1, 2]
    assert deleted == []

    old = {1, 2}
    new = {}

    added, deleted = helper.compare_old_new(old , new)
    assert added == []
    assert deleted == [1, 2]

    old = {1, 2}
    new = {3, 4}

    added, deleted = helper.compare_old_new(old , new)
    assert added == [3, 4]
    assert deleted == [1, 2]

    old = {}
    new = {}

    added, deleted = helper.compare_old_new(old , new)
    assert added == []
    assert deleted == []

    old = {1}
    new = {1}

    added, deleted = helper.compare_old_new(old , new)
    assert added == []
    assert deleted == []