"""
IOC SCANNER — v29.44 (improvement catalog P0 #2)
================================================================================
Aho-Corasick multi-pattern IOC scanner. Replaces sequential per-pattern
``re.search()`` / ``str.find()`` calls with a single automaton pass —
O(haystack_length) regardless of pattern count.

Falls back to a pure-Python Aho-Corasick implementation if no C/Rust
extension is available.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_AC_BACKEND = None
try:
    import ahocorasick  # pyahocorasick (C extension)
    _AC_BACKEND = 'pyahocorasick'
except ImportError:
    _AC_BACKEND = 'python'


class IOCMatch:
    """A single IOC match result."""
    __slots__ = ('pattern', 'ioc_type', 'start', 'end')

    def __init__(self, pattern: str, ioc_type: str, start: int, end: int):
        self.pattern = pattern
        self.ioc_type = ioc_type
        self.start = start
        self.end = end

    def __repr__(self) -> str:
        return (f'IOCMatch({self.pattern!r}, type={self.ioc_type!r}, '
                f'span=({self.start}, {self.end}))')


class _PythonAhoCorasick:
    """Pure-Python Aho-Corasick automaton (fallback)."""

    def __init__(self):
        self._goto: Dict[int, Dict[str, int]] = {0: {}}
        self._fail: Dict[int, int] = {0: 0}
        self._output: Dict[int, List[Tuple[str, str]]] = {}

    def add(self, pattern: str, ioc_type: str) -> None:
        state = 0
        for ch in pattern:
            if ch not in self._goto[state]:
                new_state = len(self._goto)
                self._goto[state][ch] = new_state
                self._goto[new_state] = {}
                self._fail[new_state] = 0
            state = self._goto[state][ch]
        self._output.setdefault(state, []).append((pattern, ioc_type))

    def finalize(self) -> None:
        from collections import deque
        queue = deque()
        for ch, state in self._goto[0].items():
            self._fail[state] = 0
            queue.append(state)
        while queue:
            current = queue.popleft()
            for ch, next_state in self._goto.get(current, {}).items():
                queue.append(next_state)
                fail_state = self._fail[current]
                while fail_state and ch not in self._goto.get(fail_state, {}):
                    fail_state = self._fail[fail_state]
                self._fail[next_state] = self._goto.get(fail_state, {}).get(
                    ch, 0)
                if next_state != self._fail[next_state]:
                    self._output.setdefault(next_state, []).extend(
                        self._output.get(self._fail[next_state], []))

    def scan(self, text: str) -> List[Tuple[str, str, int, int]]:
        matches = []
        state = 0
        for i, ch in enumerate(text):
            while state and ch not in self._goto.get(state, {}):
                state = self._fail.get(state, 0)
            state = self._goto.get(state, {}).get(ch, 0)
            if state in self._output:
                for pattern, ioc_type in self._output[state]:
                    start = i - len(pattern) + 1
                    matches.append((pattern, ioc_type, start, i + 1))
        return matches


class IOCScanner:
    """Multi-pattern IOC scanner using Aho-Corasick automaton."""

    def __init__(self, case_sensitive: bool = False):
        self._case_sensitive = case_sensitive
        self._patterns: Dict[str, str] = {}
        self._impl: Any = None
        self._finalized = False

    def add_pattern(self, pattern: str, ioc_type: str = 'ioc') -> None:
        if not self._case_sensitive:
            pattern = pattern.lower()
        self._patterns[pattern] = ioc_type
        self._finalized = False

    def add_patterns(self, patterns: Dict[str, str]) -> None:
        for pattern, ioc_type in patterns.items():
            self.add_pattern(pattern, ioc_type)

    def _ensure_finalized(self) -> None:
        if self._finalized:
            return
        if _AC_BACKEND == 'pyahocorasick':
            import ahocorasick as _ac_mod
            self._impl = _ac_mod.Automaton()
            for pattern, ioc_type in self._patterns.items():
                self._impl.add_word(pattern, (pattern, ioc_type))
            self._impl.make_automaton()
        else:
            impl = _PythonAhoCorasick()
            for pattern, ioc_type in self._patterns.items():
                impl.add(pattern, ioc_type)
            impl.finalize()
            self._impl = impl
        self._finalized = True

    def scan(self, text: str) -> List[IOCMatch]:
        """Scan text for all registered patterns. Returns IOCMatch list."""
        self._ensure_finalized()
        if not text:
            return []
        if not self._case_sensitive:
            text = text.lower()

        matches: List[IOCMatch] = []
        if _AC_BACKEND == 'pyahocorasick' and hasattr(self._impl, 'iter'):
            for end, (pattern, ioc_type) in self._impl.iter(text):
                start = end - len(pattern) + 1
                matches.append(IOCMatch(pattern, ioc_type, start, end))
        elif isinstance(self._impl, _PythonAhoCorasick):
            for m in self._impl.scan(text):
                matches.append(IOCMatch(m[0], m[1], m[2], m[3]))

        # Deduplicate overlapping matches (keep longest per start position)
        seen: set = set()
        deduped = []
        for m in sorted(matches, key=lambda x: (x.start, -(x.end - x.start))):
            key = (m.start, m.pattern)
            if key not in seen:
                seen.add(key)
                deduped.append(m)
        return deduped

    def scan_file(self, file_path: str,
                  max_size: int = 50 * 1024 * 1024) -> List[IOCMatch]:
        """Scan a file's content for IOC patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read(max_size)
            return self.scan(text)
        except Exception as exc:
            _log.debug('ioc_scanner: scan_file(%s) failed: %s', file_path, exc)
            return []

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    @property
    def backend(self) -> str:
        return _AC_BACKEND


__all__ = ['IOCScanner', 'IOCMatch', '_AC_BACKEND']