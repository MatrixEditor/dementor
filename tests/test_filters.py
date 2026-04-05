# Copyright (c) 2025-Present MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Unit tests for dementor.filters.

Covers:
- ``FilterObj``: literal, regex, and glob pattern matching
- ``Filters``: construction from strings, dicts (Target/File), and membership test
- ``in_scope``: whitelist-only, blacklist-only, combined, and no-filter paths
"""

import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from dementor.filters import FilterObj, Filters, in_scope


# ---------------------------------------------------------------------------
# FilterObj - literal matching
# ---------------------------------------------------------------------------


class TestFilterObjLiteral:
    def test_exact_match(self):
        f = FilterObj("host1")
        assert f.matches("host1") is True

    def test_no_match(self):
        f = FilterObj("host1")
        assert f.matches("host2") is False

    def test_empty_target_matches_empty_string(self):
        f = FilterObj("")
        assert f.matches("") is True

    def test_case_sensitive(self):
        f = FilterObj("HOST1")
        assert f.matches("host1") is False

    def test_ip_address_literal(self):
        f = FilterObj("192.168.1.1")
        assert f.matches("192.168.1.1") is True
        assert f.matches("192.168.1.2") is False

    def test_from_string_factory(self):
        f = FilterObj("host99")
        assert f.matches("host99") is True
        assert f.matches("host1") is False


# ---------------------------------------------------------------------------
# FilterObj - regex matching
# ---------------------------------------------------------------------------


class TestFilterObjRegex:
    def test_regex_prefix(self):
        f = FilterObj(r"re:.*\.example\.com")
        assert f.matches("api.example.com") is True
        assert f.matches("www.example.com") is True

    def test_regex_no_match(self):
        f = FilterObj(r"re:.*\.example\.com")
        assert f.matches("attacker.evil.com") is False

    def test_regex_ip_range(self):
        f = FilterObj(r"re:192\.168\.1\.[0-9]+")
        assert f.matches("192.168.1.100") is True
        assert f.matches("10.0.0.1") is False

    def test_regex_target_stripped_of_prefix(self):
        f = FilterObj(r"re:^admin$")
        assert f.target == "^admin$"

    def test_regex_pattern_not_none(self):
        f = FilterObj(r"re:foo")
        assert f.pattern is not None

    def test_literal_pattern_is_none(self):
        f = FilterObj("foo")
        assert f.pattern is None


# ---------------------------------------------------------------------------
# FilterObj - glob matching (Python 3.13+)
# ---------------------------------------------------------------------------


class TestFilterObjGlob:
    @pytest.mark.skipif(
        (sys.version_info.major, sys.version_info.minor) < (3, 13),
        reason="glob.translate requires Python 3.13+",
    )
    def test_glob_wildcard(self):
        f = FilterObj("g:*.example.com")
        assert f.matches("api.example.com") is True
        assert f.matches("www.example.com") is True
        assert f.matches("evil.net") is False

    @pytest.mark.skipif(
        (sys.version_info.major, sys.version_info.minor) >= (3, 13),
        reason="This test covers the <3.13 fallback path only",
    )
    def test_glob_pre_313_falls_back_to_literal(self):
        with pytest.warns(UserWarning, match="glob.translate"):
            f = FilterObj("g:*.example.com")
        # In fallback mode, pattern is None and matches uses exact string compare
        assert f.pattern is None
        # Target has the prefix stripped
        assert f.target == "*.example.com"

    def test_glob_target_stripped_of_prefix(self):
        if (sys.version_info.major, sys.version_info.minor) < (3, 13):
            with pytest.warns(UserWarning):  # noqa: PT030
                f = FilterObj("g:*.local")
        else:
            f = FilterObj("g:*.local")
        assert f.target == "*.local"


# ---------------------------------------------------------------------------
# FilterObj.from_file
# ---------------------------------------------------------------------------


class TestFilterObjFromFile:
    def test_from_file_loads_patterns(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write(
                textwrap.dedent("""\
                host1
                host2
                re:.*\\.admin\\.
            """)
            )
            tmppath = fh.name
        try:
            filters = FilterObj.from_file(tmppath, extra=None)
            assert len(filters) == 3
            assert any(f.matches("host1") for f in filters)
            assert any(f.matches("host2") for f in filters)
        finally:
            Path(tmppath).unlink(missing_ok=True)

    def test_from_file_nonexistent_returns_empty(self):
        result = FilterObj.from_file("/nonexistent/path/targets.txt", extra=None)
        assert result == []

    def test_from_file_attaches_extra_to_each_filter(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write("myhost\n")
            tmppath = fh.name
        try:
            extra_meta = {"source": "test"}
            filters = FilterObj.from_file(tmppath, extra=extra_meta)
            assert filters[0].extra == extra_meta
        finally:
            Path(tmppath).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Filters - construction
# ---------------------------------------------------------------------------


class TestFiltersConstruction:
    def test_from_string_list(self):
        f = Filters(["host1", "host2"])
        assert len(f.filters) == 2

    def test_from_string_list_skips_empty_strings(self):
        f = Filters(["host1", "", "host2"])
        assert len(f.filters) == 2

    def test_from_dict_with_target_key(self):
        f = Filters([{"Target": "host3", "reason": "admin"}])
        assert len(f.filters) == 1
        assert f.filters[0].matches("host3")
        assert f.filters[0].extra == {"Target": "host3", "reason": "admin"}

    def test_from_dict_with_file_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write("filehost1\nfilehost2\n")
            tmppath = fh.name
        try:
            f = Filters([{"File": tmppath}])
            assert len(f.filters) == 2
        finally:
            Path(tmppath).unlink(missing_ok=True)

    def test_dict_missing_target_and_file_skipped(self):
        f = Filters([{"other_key": "value"}])
        assert len(f.filters) == 0

    def test_mixed_string_and_dict(self):
        f = Filters(["host1", {"Target": "host2"}])
        assert len(f.filters) == 2

    def test_empty_config(self):
        f = Filters([])
        assert len(f.filters) == 0


# ---------------------------------------------------------------------------
# Filters - matching
# ---------------------------------------------------------------------------


class TestFiltersMatching:
    def test_contains_true_for_match(self):
        f = Filters(["host1", "host2"])
        assert "host1" in f
        assert "host2" in f

    def test_contains_false_for_non_match(self):
        f = Filters(["host1"])
        assert "host99" not in f

    def test_get_matched_returns_all_matching_filters(self):
        f = Filters([r"re:host[0-9]", "host5"])
        matches = f.get_matched("host5")
        # both the regex and the literal match "host5"
        assert len(matches) == 2

    def test_get_first_match_returns_first(self):
        f = Filters(["host1", r"re:host.*"])
        first = f.get_first_match("host1")
        assert first is not None
        assert first.matches("host1")

    def test_get_first_match_returns_none_when_no_match(self):
        f = Filters(["host1"])
        assert f.get_first_match("host99") is None

    def test_has_match_true(self):
        f = Filters(["host1"])
        assert f.has_match("host1") is True

    def test_has_match_false(self):
        f = Filters(["host1"])
        assert f.has_match("host99") is False

    def test_regex_filter_in_contains(self):
        f = Filters([r"re:192\.168\..*"])
        assert "192.168.1.100" in f
        assert "10.0.0.1" not in f


# ---------------------------------------------------------------------------
# in_scope - whitelist / blacklist logic
# ---------------------------------------------------------------------------


class _ScopeConfig:
    """Minimal config stub for in_scope tests."""

    def __init__(self, targets=None, ignored=None):
        if targets is not None:
            self.targets = targets
        if ignored is not None:
            self.ignored = ignored


class TestInScope:
    def test_no_filters_always_in_scope(self):
        cfg = _ScopeConfig()
        assert in_scope("anything", cfg) is True

    def test_whitelist_only_passes_match(self):
        cfg = _ScopeConfig(targets=Filters(["host1", "host2"]))
        assert in_scope("host1", cfg) is True
        assert in_scope("host2", cfg) is True

    def test_whitelist_only_blocks_non_match(self):
        cfg = _ScopeConfig(targets=Filters(["host1"]))
        assert in_scope("host99", cfg) is False

    def test_blacklist_only_blocks_match(self):
        cfg = _ScopeConfig(ignored=Filters(["host1"]))
        assert in_scope("host1", cfg) is False

    def test_blacklist_only_passes_non_match(self):
        cfg = _ScopeConfig(ignored=Filters(["host1"]))
        assert in_scope("host99", cfg) is True

    def test_whitelist_and_blacklist_combined(self):
        cfg = _ScopeConfig(
            targets=Filters(["host1", "host2"]),
            ignored=Filters(["host1"]),
        )
        # host1 is whitelisted but also blacklisted -> out of scope
        assert in_scope("host1", cfg) is False
        # host2 is whitelisted and not blacklisted -> in scope
        assert in_scope("host2", cfg) is True
        # host3 is not whitelisted -> out of scope
        assert in_scope("host3", cfg) is False

    def test_none_targets_treated_as_no_whitelist(self):
        cfg = _ScopeConfig(targets=None, ignored=Filters(["bad"]))
        assert in_scope("good", cfg) is True
        assert in_scope("bad", cfg) is False

    def test_none_ignored_treated_as_no_blacklist(self):
        cfg = _ScopeConfig(targets=Filters(["good"]), ignored=None)
        assert in_scope("good", cfg) is True
        assert in_scope("bad", cfg) is False

    def test_config_without_targets_attribute(self):
        class NoTargets:
            ignored = Filters(["blocked"])

        assert in_scope("allowed", NoTargets()) is True
        assert in_scope("blocked", NoTargets()) is False

    def test_config_without_ignored_attribute(self):
        class NoIgnored:
            targets = Filters(["allowed"])

        assert in_scope("allowed", NoIgnored()) is True
        assert in_scope("other", NoIgnored()) is False

    def test_whitelist_with_regex(self):
        cfg = _ScopeConfig(targets=Filters([r"re:10\.0\.0\.[0-9]+"]))
        assert in_scope("10.0.0.1", cfg) is True
        assert in_scope("10.0.0.255", cfg) is True
        assert in_scope("192.168.1.1", cfg) is False

    def test_blacklist_with_regex(self):
        cfg = _ScopeConfig(ignored=Filters([r"re:.*\.internal\."]))
        assert in_scope("host.internal.corp", cfg) is False
        assert in_scope("host.external.corp", cfg) is True
