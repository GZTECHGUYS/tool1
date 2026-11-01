"""Payload DB — query layer over the local payload corpus.

Roots (in order): paylads/cc/payloads (bundled 54MB corpus) plus any
cloned repos under /opt/ardf/payloads (see tools/fetch_payloads.sh).
Backdoor/webshell files are NEVER returned for fuzzing (reference only).

Usage:
    from modules.payload_db import query, categories, export, wordlist
    for p in query("xss", limit=50): ...
    path = export("auth-passwords", "/tmp/pw.txt", limit=5000)
"""
from __future__ import annotations

import csv
import os
import random
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

BUNDLED_ROOT = Path(__file__).parent.parent / "payloads" / "cc" / "payloads"


def _extra_roots() -> List[Path]:
    cands = [os.getenv("ARDF_PAYLOADS", ""),
             str(Path(__file__).parent.parent / "payloads"),
             str(Path.home() / ".ardf" / "payloads"),
             "/opt/ardf/payloads"]
    out = []
    for c in cands:
        if c and Path(c).is_dir() and Path(c) not in out:
            out.append(Path(c))
    return out

DANGEROUS_HINTS = ("backdoor", "webshell", "web-shell", "shell.",
                   "c99", "r57", "wso")

SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
            ".gz", ".7z", ".rar", ".exe", ".bin", ".pyc", ".woff", ".woff2",
            ".md", ".html"}


def _roots() -> List[Path]:
    roots = []
    if BUNDLED_ROOT.is_dir():
        roots.append(BUNDLED_ROOT)
    for child in [r for r in _extra_roots()]:
        if child.is_dir() and child not in roots:
            # a clone root holds one dir per repo: index each repo dir
            sub = [d for d in sorted(child.iterdir()) if d.is_dir()]
            roots.extend(sub if sub else [child])
    return roots


def _index_rows(root: Path) -> List[Dict[str, str]]:
    idx = root / "INDEX.tsv"
    if not idx.exists():
        return []
    try:
        with open(idx, newline="") as f:
            return list(csv.DictReader(f, delimiter="\t"))
    except Exception:
        return []


def categories() -> List[Dict[str, Any]]:
    """Per-category file/line counts across all roots (cached)."""
    import json as _json
    cache_p = Path(__file__).parent.parent / "output" / ".payloaddb_cache.json"
    try:
        cache = _json.loads(cache_p.read_text()) if cache_p.exists() else {}
    except Exception:
        cache = {}
    key = "|".join(sorted(str(r) for r in _roots()))
    try:
        tops = sum(1 for r in _roots() for _ in r.iterdir())
    except Exception:
        tops = -1
    if cache.get("key") == key and cache.get("tops") == tops and \
            cache.get("cats"):
        return cache["cats"]
    agg: Dict[str, Dict[str, int]] = {}
    for root in _roots():
        rows = _index_rows(root)
        if not rows:
            continue  # unindexed clones: run index_roots() to unlock
        for r in rows:
            cat = (r.get("category") or "misc").strip()
            if cat == "category":
                continue
            a = agg.setdefault(cat, {"files": 0, "lines": 0})
            a["files"] += 1
            try:
                a["lines"] += int(r.get("lines") or 0)
            except ValueError:
                pass
    cats = [{"category": k, **v} for k, v in sorted(agg.items())]
    try:
        cache_p.parent.mkdir(parents=True, exist_ok=True)
        cache_p.write_text(_json.dumps({"key": key, "tops": tops,
                                        "cats": cats}))
    except Exception:
        pass
    return cats


def _is_dangerous(path: str) -> bool:
    low = path.lower()
    return any(h in low for h in DANGEROUS_HINTS)


def _walk_capped(root: Path, cap: int = 1500):
    """Yield usable files, capped (multi-GB clones stall full walks)."""
    n = 0
    for f in root.rglob("*"):
        if n >= cap:
            break
        if f.is_file() and f.suffix.lower() not in SKIP_EXT:
            n += 1
            yield f


def _dir_hint(root: Path, category: str) -> bool:
    """True if the category appears in the top two directory levels."""
    try:
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if category in child.name.lower():
                return True
            for grand in child.iterdir():
                if grand.is_dir() and category in grand.name.lower():
                    return True
    except Exception:
        pass
    return False


def _files_for(root: Path, category: str) -> List[Path]:
    out = []
    rows = _index_rows(root)
    if not rows:
        return out  # unindexed clones: run index_roots() to unlock
    for r in rows:
        if (r.get("category") or "").strip() != category:
            continue
        p = root / (r.get("path") or "")
        if p.is_file() and p.suffix.lower() not in SKIP_EXT:
            out.append(p)
    return sorted(out)


def index_roots() -> Dict[str, Any]:
    """Build INDEX.tsv inside every unindexed clone root (slow, once)."""
    import subprocess
    indexer = Path(__file__).parent.parent / "paylads" / "cc" / \
        "index_payloads.py"
    done, failed = [], []
    for root in _roots():
        if (root / "INDEX.tsv").exists():
            continue
        try:
            subprocess.run([sys.executable, str(indexer), str(root)],
                           timeout=1500, capture_output=True)
            done.append(str(root))
        except Exception as e:
            failed.append(f"{root}: {str(e)[:120]}")
    return {"indexed": done, "failed": failed}


def query(category: str, limit: int = 200, dedupe: bool = True,
          allow_dangerous: bool = False,
          shuffle: bool = False) -> List[str]:
    """Payload strings for a category (never backdoors unless asked)."""
    seen, out = set(), []
    files: List[Path] = []
    for root in _roots():
        files.extend(_files_for(root, category))
    if shuffle:
        random.shuffle(files)
    for path in files:
        if _is_dangerous(str(path)) and not allow_dangerous:
            continue
        try:
            with open(path, errors="ignore") as f:
                for line in f:
                    s = line.rstrip("\n")
                    if not s or len(s) > 4000:
                        continue
                    if dedupe:
                        if s in seen:
                            continue
                        seen.add(s)
                    out.append(s)
                    if len(out) >= limit:
                        return out
        except Exception:
            continue
    return out


def export(category: str, dest: str, limit: int = 5000,
           allow_dangerous: bool = False) -> str:
    """Write a category to a wordlist file (for hydra/ffuf/dir_enum)."""
    payloads = query(category, limit=limit, allow_dangerous=allow_dangerous)
    Path(dest).write_text("\n".join(payloads) + "\n")
    return dest


def wordlist(kind: str) -> Optional[str]:
    """Best local file for passwords / users / dirs, or None."""
    wants = {"passwords": ("wordlists-user-passwd", "passwds", ".txt"),
             "users": ("wordlists-user-passwd", "names", ".txt"),
             "dirs": ("directories", "dir", ".txt")}
    want_dir, want_file, ext = wants.get(kind, ("", "", ""))
    if not want_dir:
        return None
    for root in _roots():
        cands: List[Path] = []
        for r in _index_rows(root):
            p = root / (r.get("path") or "")
            low = str(p).lower()
            if want_dir in low and want_file in low and \
                    not _is_dangerous(low):
                cands.append(p)
        if not cands and _dir_hint(root, want_dir.split("-")[0]):
            for f in _walk_capped(root):
                low = str(f).lower()
                if want_dir in low and want_file in low and \
                        not _is_dangerous(low):
                    cands.append(f)
                    break
        for c in sorted(cands):
            try:
                if c.is_file() and c.stat().st_size > 100:
                    return str(c)
            except Exception:
                continue
    return None


def stats() -> Dict[str, Any]:
    cats = categories()
    return {"roots": [str(r) for r in _roots()],
            "categories": cats,
            "total_files": sum(c["files"] for c in cats),
            "total_lines": sum(c["lines"] for c in cats)}


def brute_pair() -> Dict[str, Optional[str]]:
    """User/pass wordlist paths for brute-forcers (payload DB first)."""
    users = wordlist("users")
    passwords = wordlist("passwords")
    if not users:
        users = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    if not passwords:
        passwords = "/usr/share/wordlists/rockyou.txt"
    import os as _os
    return {"users": users if _os.path.exists(users or "") else None,
            "passwords": passwords if _os.path.exists(passwords or "")
            else None}
