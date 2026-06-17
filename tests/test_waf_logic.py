"""
test_waf_logic.py — WAF logic parity check (Python mirror).

COVERAGE NOTE: This file mirrors BLOCKED_PATTERNS from node-app/src/middleware/waf.js
in Python (re module) so the parity can be verified without a running Node.js process.
It validates Python-reconstructed logic, NOT the shipped waf.js code.

The authoritative execution tests for the real waf.js module live in:
    node-app/tests/waf.test.js  (jest + supertest, 28 tests, npm test)

If waf.js patterns change, update the BLOCKED_PATTERNS dicts below to stay in parity.
"""
import re
import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Replicate BLOCKED_PATTERNS from waf.js in Python
# ─────────────────────────────────────────────────────────────────────────────

# SQLi: ' OR
RE_SQLI_OR = re.compile(r"'\s*OR\s", re.IGNORECASE)

# SQLi: UNION SELECT — blocked when separated by literal space or tab ONLY
# [ \t]+ so newlines are NOT blocked (enabling %0a bypass, feature 57)
RE_UNION_SELECT = re.compile(r"UNION[ \t]+(?:ALL[ \t]+)?SELECT")

# Script-tag: inline (no src)
RE_SCRIPT_INLINE = re.compile(r"<script(?![^>]*\ssrc\s*=)[^>]*>", re.IGNORECASE)

# Script-tag: external src with https:// or http://
RE_SCRIPT_ABSOLUTE = re.compile(r"<script[^>]+src\s*=\s*[\"']?\s*https?://", re.IGNORECASE)

# Script-tag: protocol-relative src (//)
RE_SCRIPT_PROREL = re.compile(r"<script[^>]+src\s*=\s*[\"']?\s*//", re.IGNORECASE)

# Event handler: on[a-z]+(optional whitespace)=
RE_EVENT_HANDLER = re.compile(r"\bon[a-zA-Z]+\s*=", re.IGNORECASE)

# XXE: ENTITY with http/https (NOT file://)
RE_XXE_HTTP = re.compile(r"<!ENTITY[^>]*https?://", re.IGNORECASE)


def blocked(value: str) -> bool:
    """Return True if any WAF pattern matches the value."""
    return any([
        RE_SQLI_OR.search(value),
        RE_UNION_SELECT.search(value),
        RE_SCRIPT_INLINE.search(value),
        RE_SCRIPT_ABSOLUTE.search(value),
        RE_SCRIPT_PROREL.search(value),
        RE_EVENT_HANDLER.search(value),
        RE_XXE_HTTP.search(value),
    ])


# ─────────────────────────────────────────────────────────────────────────────
# SQLi: ' OR tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSqliOrRule:
    def test_basic_or(self):
        assert blocked("' OR 1=1")

    def test_or_with_leading_space(self):
        assert blocked("'  OR 1=1")

    def test_or_lowercase(self):
        assert blocked("' or 1=1")

    def test_or_mixed_case(self):
        assert blocked("' Or 1=1")

    def test_benign_word_or(self):
        # 'order' contains 'or' but not surrounded by SQL context — pattern requires '
        assert not blocked("orange order")

    def test_or_without_apostrophe(self):
        # Requires leading ' — plain OR is not blocked
        assert not blocked("OR 1=1")

    def test_boolean_blind_and_not_blocked(self):
        """
        Feature 36: WAF does NOT block boolean-blind SQL (AND 1=1).
        None of the WAF patterns match 'AND 1=1'.
        """
        assert not blocked("AND 1=1")
        assert not blocked("1 AND 1=1--")
        assert not blocked("test AND sleep(5)--")


# ─────────────────────────────────────────────────────────────────────────────
# SQLi: UNION SELECT tests (features 56, 57, 58)
# ─────────────────────────────────────────────────────────────────────────────

class TestUnionSelectRule:
    def test_union_space_select_blocked(self):
        assert blocked("UNION SELECT 1,2,3")

    def test_union_tab_select_blocked(self):
        assert blocked("UNION\tSELECT 1,2,3")

    def test_union_all_select_blocked(self):
        assert blocked("UNION ALL SELECT 1,2,3")

    # Feature 56: comment bypass
    def test_union_comment_select_not_blocked(self):
        """Feature 56: UNION/**/SELECT bypasses [ \t]+ rule."""
        assert not blocked("UNION/**/SELECT 1,2")

    # Feature 57: newline bypass (URL-decoded %0a)
    def test_union_newline_select_not_blocked(self):
        """Feature 57: UNION\nSELECT bypasses [ \t]+ rule (newline not in charset)."""
        assert not blocked("UNION\nSELECT 1,2")

    # Feature 58: case bypass
    def test_union_mixed_case_not_blocked(self):
        """Feature 58: UnIoN SeLeCt bypasses case-sensitive pattern."""
        # The JS WAF regex is case-SENSITIVE (no /i flag on UNION rule)
        assert not blocked("UnIoN SeLeCt 1,2")

    def test_union_two_spaces_blocked(self):
        # Multiple spaces still match [ \t]+
        assert blocked("UNION  SELECT 1,2")


# ─────────────────────────────────────────────────────────────────────────────
# Script-tag tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScriptTagRule:
    def test_inline_script_blocked(self):
        assert blocked("<script>alert(1)</script>")

    def test_inline_script_with_type_blocked(self):
        assert blocked("<script type='text/javascript'>x()</script>")

    def test_external_https_blocked(self):
        assert blocked('<script src="https://evil.com/x.js">')

    def test_external_http_blocked(self):
        assert blocked('<script src="http://evil.com/x.js">')

    def test_protocol_relative_blocked(self):
        assert blocked('<script src="//evil.com/x.js">')

    def test_same_origin_src_not_blocked(self):
        """Same-origin /path src is explicitly PERMITTED (CS-01 JSONP vector)."""
        assert not blocked('<script src="/api/products/search?callback=fn">')

    def test_same_origin_no_scheme_not_blocked(self):
        assert not blocked('<script src="/static/app.js">')


# ─────────────────────────────────────────────────────────────────────────────
# Event handler tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEventHandlerRule:
    def test_onerror_blocked(self):
        assert blocked('<img src=x onerror=alert(1)>')

    def test_onload_blocked(self):
        assert blocked('<body onload=init()>')

    def test_onerror_space_before_equals_blocked(self):
        """Whitespace before = must be blocked (G4-R1 fix: added \\s* to pattern)."""
        assert blocked('<img src=x onerror =alert(1)>')

    def test_onerror_tab_before_equals_blocked(self):
        assert blocked('<img src=x onerror\t=alert(1)>')

    def test_onclick_blocked(self):
        assert blocked('<div onclick=evil()>')

    def test_onmouseover_blocked(self):
        assert blocked('<a href=# onmouseover=x>')

    def test_benign_word_containing_on(self):
        # 'online' doesn't match \bon[a-zA-Z]+\s*= because there's no = after it
        assert not blocked("This is online content")


# ─────────────────────────────────────────────────────────────────────────────
# XXE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestXxeRule:
    def test_entity_https_blocked(self):
        assert blocked('<!ENTITY xxe SYSTEM "https://evil.com/data">')

    def test_entity_http_blocked(self):
        assert blocked('<!ENTITY xxe SYSTEM "http://evil.com/data">')

    def test_entity_file_not_blocked(self):
        """file:// URI is NOT blocked — intentional SS-02 exploit vector."""
        assert not blocked('<!ENTITY xxe SYSTEM "file:///app/flags/ss02.txt">')

    def test_entity_without_uri_not_blocked(self):
        # Plain ENTITY without URL is not blocked
        assert not blocked('<!ENTITY nbsp "&#160;">')
