from scanner.core.config import ScopeConfig
from scanner.core.scope import Scope
from scanner.utils.url import normalize_url, parameter_names


def test_normalize_adds_https_and_removes_fragment() -> None:
    assert normalize_url("Example.com/a/../b#frag") == "https://example.com/b"


def test_scope_blocks_out_of_scope_hosts() -> None:
    scope = Scope(ScopeConfig(allowed_hosts=frozenset({"example.com"})))
    assert scope.is_allowed("https://example.com/")
    assert not scope.is_allowed("https://evil.example.net/")


def test_parameter_names_are_deduplicated() -> None:
    assert parameter_names("https://example.com/?a=1&b=2&a=3") == ("a", "b")
