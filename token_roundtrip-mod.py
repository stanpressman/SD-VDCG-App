from __future__ import annotations

import csv
import hashlib
import hmac
import secrets
import re
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Set, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

WORD_PATTERN = re.compile(r"[A-Za-z']+|[^A-Za-z']+")

# Optional matplotlib for plotting
try:
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Optional scipy for chi-squared p-value
try:
    from scipy import stats as scipy_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

# Optional KMAC (PyCryptodome)
try:
    from Crypto.Hash import KMAC256
    HAS_KMAC = True
except ImportError:
    HAS_KMAC = False

HASH_OPTIONS = ["HMAC-SHA256", "HMAC-SHA512", "BLAKE2b"] + (["KMAC256"] if HAS_KMAC else [])


@dataclass
class EncodedWord:
    token: int | None
    case_style: str
    original: str


@dataclass
class SessionDiffResult:
    """Result of cross-session difference test."""
    word: str
    num_pairs: int
    truncation_bits: int
    hamming_full_mean: float
    hamming_full_std: float
    hamming_full_min: int
    hamming_full_max: int
    hamming_token_mean: float
    hamming_token_std: float
    hamming_token_min: int
    hamming_token_max: int
    elapsed: float


@dataclass
class BucketTestResult:
    """Result of bucket distribution test."""
    word: str
    num_runs: int
    truncation_bits: int
    num_buckets: int
    counts: List[int]
    elapsed: float
    stats: Dict[str, float]


@dataclass
class MinTokenDistResult:
    """Result of min token distance test (how close to collision per session)."""
    message_words: List[str]
    num_sessions: int
    truncation_bits: int
    session_min_distances: List[Tuple[int, int]]  # (session_num, min_distance)
    elapsed: float


@dataclass
class SweepResult:
    """Collision sweep result for one bit width (message-word collisions)."""
    bit_width: int
    loops: int
    avg_collisions: float
    min_collisions: int
    max_collisions: int
    expected_collisions: float
    std_dev: float
    message_word_count: int


def expected_collisions(n: int, b: int) -> float:
    """Birthday bound: expected collisions for n items in 2^b buckets."""
    return (n * n) / (2 ** (b + 1))


def build_epoch_hmac_key(
    passphrase: str,
    chain_state: str,
    extra: str,
    *,
    loop_index: int,
    include_timestamp: bool,
    include_random_salt: bool,
) -> bytes:
    """Material for the HMAC key: bind passphrase / chain / extras, then vary per epoch.

    Each component is UTF-8; pieces are joined with ASCII RS (0x1e) to reduce ambiguity.
    When *include_timestamp* or *include_random_salt* is true, successive calls yield
    different keys even if static inputs are unchanged — i.e. a new epoch each time.
    """
    parts: List[bytes] = [
        b"QS-EPOCH-v1",
        passphrase.encode("utf-8"),
        chain_state.encode("utf-8"),
        extra.encode("utf-8"),
        f"loop={loop_index}".encode("ascii"),
    ]
    if include_timestamp:
        parts.append(datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f").encode("ascii"))
    if include_random_salt:
        parts.append(secrets.token_bytes(16))
    return b"\x1e".join(parts)


def unordered_collision_pairs_from_mapping(word_to_token: Dict[str, int]) -> List[Tuple[str, str]]:
    """All unordered word pairs that share the same truncated token (same bucket)."""
    token_to_words: Dict[int, List[str]] = defaultdict(list)
    for w, t in word_to_token.items():
        token_to_words[t].append(w)
    pairs: List[Tuple[str, str]] = []
    for ws in token_to_words.values():
        if len(ws) < 2:
            continue
        s = sorted(ws)
        for i in range(len(s)):
            for j in range(i + 1, len(s)):
                pairs.append((s[i], s[j]))
    return pairs


@dataclass
class DictPrefixCollisionLoop:
    """One epoch: first-N dictionary words hashed under that epoch's HMAC key."""
    loop_number: int
    pair_count: int
    pairs: List[Tuple[str, str]]


@dataclass
class DictPrefixCollisionStudy:
    """Multi-epoch collision mapping for a prefix of the dictionary file order."""
    n_dictionary_words: int
    truncation_bits: int
    expected_pair_count: float
    loops: int
    loop_results: List[DictPrefixCollisionLoop]
    elapsed: float
    epoch_key_summary: str


def run_dictionary_prefix_collision_study(
    dictionary_path: Path,
    num_words: int,
    truncation_bits: int,
    num_loops: int,
    hash_type: str = "HMAC-SHA256",
    passphrase: str = "",
    chain_state: str = "",
    extra: str = "",
    include_timestamp_per_epoch: bool = True,
    include_random_salt_per_epoch: bool = True,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> DictPrefixCollisionStudy:
    """Hash the first ``num_words`` dictionary entries (file order) per epoch; report token collisions.

    The HMAC key for each epoch is derived from *passphrase*, *chain_state*, *extra*,
    the epoch index, and optionally a fresh UTC timestamp and/or random salt so collision
    geometry changes whenever those bindings change (new chain state, new passphrase, etc.).
    """
    words = load_dictionary(dictionary_path)
    if num_words < 2:
        raise ValueError("Need at least 2 words from the dictionary.")
    if num_words > len(words):
        raise ValueError(
            f"Dictionary has {len(words)} word(s); cannot take the first {num_words}."
        )
    if not (3 <= truncation_bits <= 128):
        raise ValueError("Truncation must be between 3 and 128 bits.")
    prefix = words[:num_words]
    word_entries: List[Tuple[str, bytes]] = [(w, w.encode("utf-8")) for w in prefix]
    expected_pairs = expected_collisions(num_words, truncation_bits)
    loop_results: List[DictPrefixCollisionLoop] = []
    t0 = time.perf_counter()

    summary_bits = [
        "epoch key = passphrase + chain state + extra (UTF-8)",
        f"per-epoch: loop index",
    ]
    if include_timestamp_per_epoch:
        summary_bits.append("fresh UTC timestamp each epoch")
    if include_random_salt_per_epoch:
        summary_bits.append("random 16-byte salt each epoch")
    epoch_key_summary = "; ".join(summary_bits)

    for loop_idx in range(1, num_loops + 1):
        if progress_callback:
            progress_callback(loop_idx, num_loops)
        hmac_key = build_epoch_hmac_key(
            passphrase,
            chain_state,
            extra,
            loop_index=loop_idx,
            include_timestamp=include_timestamp_per_epoch,
            include_random_salt=include_random_salt_per_epoch,
        )
        word_to_token, _, _ = build_token_maps(
            word_entries, hmac_key, truncation_bits, hash_type
        )
        pairs = unordered_collision_pairs_from_mapping(word_to_token)
        loop_results.append(
            DictPrefixCollisionLoop(
                loop_number=loop_idx,
                pair_count=len(pairs),
                pairs=pairs,
            )
        )

    elapsed = time.perf_counter() - t0
    return DictPrefixCollisionStudy(
        n_dictionary_words=num_words,
        truncation_bits=truncation_bits,
        expected_pair_count=expected_pairs,
        loops=num_loops,
        loop_results=loop_results,
        elapsed=elapsed,
        epoch_key_summary=epoch_key_summary,
    )


def run_bucket_distribution(
    word: str,
    num_runs: int,
    truncation_bits: int,
    hash_type: str = "HMAC-SHA256",
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Tuple[List[int], float]:
    """Run HMAC distribution test: same word, different keys each run.
    Returns (bucket_counts, elapsed_seconds). Bucket count length = 2^truncation_bits."""
    num_buckets = 1 << truncation_bits
    counts = [0] * num_buckets
    word_bytes = word.encode("utf-8")
    t0 = time.perf_counter()

    for run in range(num_runs):
        if progress_callback:
            progress_callback(run + 1, num_runs)
        session_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        secret_salt = secrets.token_bytes(16)
        hmac_key = session_timestamp.encode("utf-8") + secret_salt
        bucket_idx = word_token(word_bytes, hmac_key, truncation_bits, hash_type)
        counts[bucket_idx] += 1

    elapsed = time.perf_counter() - t0
    return counts, elapsed


def run_session_difference(
    word: str,
    num_pairs: int,
    truncation_bits: int,
    hash_type: str = "HMAC-SHA256",
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> SessionDiffResult:
    """Run cross-session difference test: same word, two different keys per pair.
    Measures Hamming distance (full HMAC and truncated token) to verify avalanche/independence."""
    word_bytes = word.encode("utf-8")
    hamming_full_list: List[int] = []
    hamming_token_list: List[int] = []
    t0 = time.perf_counter()

    for i in range(num_pairs):
        if progress_callback:
            progress_callback(i + 1, num_pairs)
        key1 = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f").encode("utf-8") + secrets.token_bytes(16)
        key2 = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f").encode("utf-8") + secrets.token_bytes(16)
        hmac1_full = word_hmac_full(word_bytes, key1, hash_type)
        hmac2_full = word_hmac_full(word_bytes, key2, hash_type)
        token1 = word_token(word_bytes, key1, truncation_bits, hash_type)
        token2 = word_token(word_bytes, key2, truncation_bits, hash_type)
        hamming_full_list.append(hamming_distance(hmac1_full, hmac2_full, 256))
        hamming_token_list.append(hamming_distance(token1, token2, truncation_bits))

    elapsed = time.perf_counter() - t0
    return SessionDiffResult(
        word=word,
        num_pairs=num_pairs,
        truncation_bits=truncation_bits,
        hamming_full_mean=statistics.mean(hamming_full_list),
        hamming_full_std=statistics.stdev(hamming_full_list) if num_pairs > 1 else 0.0,
        hamming_full_min=min(hamming_full_list),
        hamming_full_max=max(hamming_full_list),
        hamming_token_mean=statistics.mean(hamming_token_list),
        hamming_token_std=statistics.stdev(hamming_token_list) if num_pairs > 1 else 0.0,
        hamming_token_min=min(hamming_token_list),
        hamming_token_max=max(hamming_token_list),
        elapsed=elapsed,
    )


def generate_tokenization_preview(
    message: str, truncation_bits: int, hash_type: str = "HMAC-SHA256"
) -> Tuple[str, str, List[Tuple[str, int]]]:
    """Generate one session's tokenization. Returns (timestamp, salt_hex, word_token_pairs)."""
    session_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    secret_salt = secrets.token_bytes(16)
    key = session_timestamp.encode("utf-8") + secret_salt
    message_parts = tokenize_message(message)
    message_words = list(dict.fromkeys(p[1].lower() for p in message_parts if p[0] == "word"))
    if not message_words:
        return session_timestamp, secret_salt.hex(), []
    word_entries = [(w, w.encode("utf-8")) for w in message_words]
    word_to_token, _, _ = build_token_maps(word_entries, key, truncation_bits, hash_type)
    pairs = [(w, word_to_token[w]) for w in message_words]
    return session_timestamp, secret_salt.hex(), pairs


def run_min_token_distance(
    message: str,
    num_sessions: int,
    truncation_bits: int,
    hash_type: str = "HMAC-SHA256",
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> MinTokenDistResult:
    """For each session, compute min Hamming distance between any two message-word tokens.
    min_distance=0 means collision; higher = farther from collision."""
    message_parts = tokenize_message(message)
    message_words = list(dict.fromkeys(p[1].lower() for p in message_parts if p[0] == "word"))
    if len(message_words) < 2:
        raise ValueError("Message must have at least 2 unique words.")
    word_entries = [(w, w.encode("utf-8")) for w in message_words]
    session_min_distances: List[Tuple[int, int]] = []
    t0 = time.perf_counter()

    for sess in range(num_sessions):
        if progress_callback:
            progress_callback(sess + 1, num_sessions)
        key = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f").encode("utf-8") + secrets.token_bytes(16)
        word_to_token, _, _ = build_token_maps(word_entries, key, truncation_bits, hash_type)
        tokens = [word_to_token[w] for w in message_words]
        min_dist = truncation_bits + 1
        for i in range(len(tokens)):
            for j in range(i + 1, len(tokens)):
                d = hamming_distance(tokens[i], tokens[j], truncation_bits)
                if d < min_dist:
                    min_dist = d
                    if min_dist == 0:
                        break
            if min_dist == 0:
                break
        session_min_distances.append((sess + 1, min_dist))

    elapsed = time.perf_counter() - t0
    return MinTokenDistResult(
        message_words=message_words,
        num_sessions=num_sessions,
        truncation_bits=truncation_bits,
        session_min_distances=session_min_distances,
        elapsed=elapsed,
    )


def compute_bucket_stats(
    counts: List[int], num_runs: int, num_buckets: int
) -> Dict[str, float]:
    """Compute distribution statistics. Returns mean, std_dev, min, max, empty_buckets, chi_sq, p_value."""
    mean = num_runs / num_buckets
    std_dev = statistics.stdev(counts) if num_buckets > 1 else 0.0
    min_c = min(counts)
    max_c = max(counts)
    empty = sum(1 for c in counts if c == 0)
    chi_sq = sum((c - mean) ** 2 / mean for c in counts) if mean > 0 else 0.0
    p_value: Optional[float] = None
    if HAS_SCIPY and mean > 0:
        p_value = float(scipy_stats.chi2.sf(chi_sq, num_buckets - 1))
    return {
        "mean": mean,
        "std_dev": std_dev,
        "min": float(min_c),
        "max": float(max_c),
        "empty_buckets": float(empty),
        "chi_sq": chi_sq,
        "p_value": p_value,
    }


def format_bucket_output(
    counts: List[int], truncation_bits: int, num_runs: int, stats: Dict[str, float]
) -> str:
    """Format bucket index row and count row. For 8 bits show all; for 16+ bin into 256."""
    num_buckets = len(counts)
    max_display = 256

    if num_buckets <= max_display:
        indices = list(range(num_buckets))
        display_counts = counts
    else:
        bin_size = num_buckets // max_display
        display_counts = [
            sum(counts[i * bin_size : (i + 1) * bin_size])
            for i in range(max_display)
        ]
        indices = list(range(max_display))

    col_width = max(4, len(str(max(display_counts))) + 1)
    row1 = " | ".join(f"{i:^{col_width}}" for i in indices)
    row2 = " | ".join(f"{c:^{col_width}}" for c in display_counts)

    summary_lines = [
        "STATISTICS:",
        f"  Mean:        {stats['mean']:.4f}  (expected per bucket)",
        f"  Std Dev:     {stats['std_dev']:.4f}",
        f"  Min:         {int(stats['min'])}",
        f"  Max:         {int(stats['max'])}",
        f"  Empty:       {int(stats['empty_buckets'])} buckets",
        f"  Chi-squared: {stats['chi_sq']:.2f}",
    ]
    if stats.get("p_value") is not None:
        summary_lines.append(f"  P-value:     {stats['p_value']:.4f}  (high = consistent with uniform)")
    summary_lines.append("")

    if num_buckets > max_display:
        bin_size = num_buckets // max_display
        header = f"Binned view: {num_buckets} buckets → {max_display} bins (each bin = {bin_size} buckets)\n"
    else:
        header = ""
    return "\n".join(summary_lines) + header + "Bucket: " + row1 + "\nCount:  " + row2


def min_token_dist_result_to_csv_rows(result: MinTokenDistResult) -> List[List[str]]:
    """Convert min token distance result to CSV: SessionNumber, MinDistance."""
    rows = [
        ["WordCount", "NumSessions", "TruncationBits", "Collisions", "ElapsedSec"],
        [str(len(result.message_words)), str(result.num_sessions), str(result.truncation_bits),
         str(sum(1 for _, d in result.session_min_distances if d == 0)), f"{result.elapsed:.6f}"],
        [],
        ["SessionNumber", "MinDistance"],
    ]
    for sess_num, min_dist in result.session_min_distances:
        rows.append([str(sess_num), str(min_dist)])
    return rows


def session_diff_result_to_csv_rows(result: SessionDiffResult) -> List[List[str]]:
    """Convert session diff result to CSV rows."""
    return [
        ["Word", "NumPairs", "TruncationBits", "HammingFullMean", "HammingFullStd", "HammingFullMin", "HammingFullMax",
         "HammingTokenMean", "HammingTokenStd", "HammingTokenMin", "HammingTokenMax", "ElapsedSec"],
        [result.word, str(result.num_pairs), str(result.truncation_bits),
         f"{result.hamming_full_mean:.4f}", f"{result.hamming_full_std:.4f}",
         str(result.hamming_full_min), str(result.hamming_full_max),
         f"{result.hamming_token_mean:.4f}", f"{result.hamming_token_std:.4f}",
         str(result.hamming_token_min), str(result.hamming_token_max),
         f"{result.elapsed:.6f}"],
    ]


def bucket_result_to_csv_rows(result: BucketTestResult) -> List[List[str]]:
    """Convert bucket test result to CSV rows: summary first, then bucket data."""
    s = result.stats
    p_val = f"{s['p_value']:.6f}" if s.get("p_value") is not None else ""
    rows = [
        ["Word", "Runs", "TruncationBits", "Buckets", "Mean", "StdDev", "Min", "Max", "EmptyBuckets", "ChiSq", "PValue", "ElapsedSec"],
        [result.word, str(result.num_runs), str(result.truncation_bits), str(result.num_buckets),
         f"{s['mean']:.6f}", f"{s['std_dev']:.6f}", str(int(s['min'])), str(int(s['max'])),
         str(int(s['empty_buckets'])), f"{s['chi_sq']:.6f}", p_val, f"{result.elapsed:.6f}"],
        [],
        ["BucketIndex", "Count"],
    ]
    max_bucket_rows = 100000  # Limit to avoid huge CSV for 16+ bits
    for i, c in enumerate(result.counts):
        if i >= max_bucket_rows:
            rows.append([f"(truncated - {result.num_buckets - max_bucket_rows} more buckets omitted)", ""])
            break
        rows.append([str(i), str(c)])
    return rows


def format_elapsed(seconds: float) -> str:
    """Format elapsed time for display (e.g. '12.34 s' or '1m 23.45s')."""
    if seconds < 60:
        return f"{seconds:.2f} s"
    mins = int(seconds // 60)
    secs = seconds % 60
    return f"{mins}m {secs:.2f}s"


@dataclass
class RoundTripResult:
    """Single loop result for table display."""
    loop_number: int
    dictionary_size: int
    session_timestamp: str
    encode_dict_time_ms: float
    encode_msg_time_ms: float
    decode_dict_time_ms: float
    decode_msg_time_ms: float
    total_time_ms: float
    collision_count: int
    token_value_the: Optional[int]
    verification_result: str
    word_mismatches: int
    reconstructed_message: str


def load_dictionary(path: Path) -> List[str]:
    """Load and clean the dictionary, lowercasing and stripping suffix notation."""
    words: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        first_line = handle.readline().strip()
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            base = raw.split("/", 1)[0]
            words.append(base.lower())
    return words


def _hash_digest(word_bytes: bytes, key: bytes, hash_type: str) -> bytes:
    """Compute keyed hash digest. Returns 32+ bytes depending on hash type."""
    if hash_type == "HMAC-SHA256":
        return hmac.new(key, word_bytes, hashlib.sha256).digest()
    if hash_type == "HMAC-SHA512":
        return hmac.new(key, word_bytes, hashlib.sha512).digest()
    if hash_type == "BLAKE2b":
        return hashlib.blake2b(word_bytes, key=key, digest_size=64).digest()
    if hash_type == "KMAC256" and HAS_KMAC:
        # KMAC256 requires key >= 32 bytes; pad if needed
        k = key if len(key) >= 32 else key + b"\x00" * (32 - len(key))
        return KMAC256.new(key=k, mac_len=32).update(word_bytes).digest()
    raise ValueError(f"Unknown hash type: {hash_type}")


def word_token(word_bytes: bytes, key: bytes, truncation_bits: int, hash_type: str = "HMAC-SHA256") -> int:
    """Return lower N bits of keyed hash output."""
    digest = _hash_digest(word_bytes, key, hash_type)
    num_bytes = (truncation_bits + 7) // 8
    mask = (1 << truncation_bits) - 1
    return int.from_bytes(digest[: max(num_bytes, 32)], "big") & mask


def word_hmac_full(word_bytes: bytes, key: bytes, hash_type: str = "HMAC-SHA256") -> int:
    """Return first 256 bits of digest as int (for cross-session Hamming comparison)."""
    digest = _hash_digest(word_bytes, key, hash_type)
    return int.from_bytes(digest[:32], "big")


def hamming_distance(a: int, b: int, bits: int) -> int:
    """Number of differing bits between two integers (both truncated to 'bits' width)."""
    mask = (1 << bits) - 1
    return ((a & mask) ^ (b & mask)).bit_count()


def build_token_maps(
    word_entries: List[Tuple[str, bytes]],
    key: bytes,
    truncation_bits: int,
    hash_type: str = "HMAC-SHA256",
) -> Tuple[Dict[str, int], Dict[int, str], int]:
    """Return (word->token, token->word, collision_count) using keyed hash."""
    word_to_token: Dict[str, int] = {}
    token_to_word: Dict[int, str] = {}
    collisions = 0

    for word, word_bytes in word_entries:
        token = word_token(word_bytes, key, truncation_bits, hash_type)
        if token in token_to_word and token_to_word[token] != word:
            collisions += 1
        word_to_token[word] = token
        token_to_word.setdefault(token, word)
    return word_to_token, token_to_word, collisions


def count_message_word_collisions(
    word_to_token: Dict[str, int], message_words: List[str]
) -> int:
    """Count collisions among message words: how many message words map to a token
    already used by another message word. This is what matters for communications."""
    token_to_message_words: Dict[int, List[str]] = {}
    for word in message_words:
        token = word_to_token.get(word)
        if token is not None:
            token_to_message_words.setdefault(token, []).append(word)
    collisions = 0
    for words_at_token in token_to_message_words.values():
        if len(words_at_token) > 1:
            collisions += len(words_at_token) - 1  # first is fine, rest collide
    return collisions


def detect_case(word: str) -> str:
    if word.isupper():
        return "upper"
    if word.istitle():
        return "title"
    if word.islower():
        return "lower"
    return "mixed"


def apply_case(word: str, case_style: str, original: str) -> str:
    if case_style == "upper":
        return word.upper()
    if case_style == "title":
        return word.title()
    if case_style == "lower":
        return word.lower()
    return original


def tokenize_message(message: str) -> List[Tuple[str, str, str]]:
    """Return list of (kind, text, case_style). kind is 'word' or 'sep'."""
    parts: List[Tuple[str, str, str]] = []
    for chunk in WORD_PATTERN.findall(message):
        if re.fullmatch(r"[A-Za-z']+", chunk):
            parts.append(("word", chunk, detect_case(chunk)))
        else:
            parts.append(("sep", chunk, ""))
    return parts


# Fixed wire size per tokenized unit when comparing to plain text / dictionary index (paper/SDK sizing).
HMAC_WIRE_BITS = 128


def dictionary_word_to_first_index(dictionary_words: List[str]) -> Dict[str, int]:
    """Map each word to the index of its first occurrence in the dictionary file order."""
    out: Dict[str, int] = {}
    for i, w in enumerate(dictionary_words):
        if w not in out:
            out[w] = i
    return out


def index_storage_byte_width(max_index_exclusive: int) -> int:
    """Bytes to store one index in range [0, max_index_exclusive - 1]."""
    if max_index_exclusive <= 1:
        return 1
    return ((max_index_exclusive - 1).bit_length() + 7) // 8


def format_message_payload_size_report(
    message: str,
    dictionary_words: List[str],
    hmac_wire_bits: int = HMAC_WIRE_BITS,
) -> str:
    """Compare payload size under three models: 128-bit token per piece, UTF-8 per character, dict index + literal seps."""
    parts = tokenize_message(message)
    dict_size = len(dictionary_words)
    word_to_idx = dictionary_word_to_first_index(dictionary_words)
    idx_bytes = index_storage_byte_width(dict_size) if dict_size else 1

    n_word_pieces = sum(1 for p in parts if p[0] == "word")
    n_sep_pieces = sum(1 for p in parts if p[0] == "sep")
    total_pieces = len(parts)

    bytes_per_hmac = (hmac_wire_bits + 7) // 8
    hmac_total_bytes = total_pieces * bytes_per_hmac

    # Character model: one piece per Unicode code point; payload bytes = UTF-8 length of entire message.
    char_pieces = len(message)
    utf8_payload = message.encode("utf-8")
    char_total_bytes = len(utf8_payload)

    dict_word_bytes = 0
    dict_sep_bytes = 0
    missing: List[str] = []
    for kind, text, _ in parts:
        if kind == "word":
            canon = text.lower()
            if canon not in word_to_idx:
                missing.append(text)
            dict_word_bytes += idx_bytes
        else:
            dict_sep_bytes += len(text.encode("utf-8"))

    dict_total_bytes = dict_word_bytes + dict_sep_bytes
    lines: List[str] = [
        "Message payload size (no framing / transmission overhead)",
        "",
        f"Tokenizer: {n_word_pieces} word piece(s), {n_sep_pieces} non-word piece(s), {total_pieces} total piece(s).",
        f"(Non-words are separator runs: spaces, punctuation, etc.; future plan: each becomes its own fixed-width token.)",
        "",
        f"1) Session tokens ({hmac_wire_bits}-bit HMAC value per piece)",
        f"   Pieces of data: {total_pieces}",
        f"   Payload bytes:   {hmac_total_bytes}  ({total_pieces} × {bytes_per_hmac} bytes)",
        "",
        "2) Plain characters (UTF-8)",
        f"   Pieces of data: {char_pieces}  (Unicode code points, same as len(message) in Python)",
        f"   Payload bytes:   {char_total_bytes}  (UTF-8 encoding of full message)",
        "",
        f"3) Dictionary index + literal non-words",
        f"   Dictionary word count (file order): {dict_size}",
        f"   Index byte width: {idx_bytes} byte(s) per word piece (covers indices 0 … {max(dict_size - 1, 0)})",
        f"   Pieces of data: {total_pieces}  ({n_word_pieces} word indices + {n_sep_pieces} non-word segment(s))",
        f"   Payload bytes:   {dict_total_bytes}  ({n_word_pieces} × {idx_bytes} + {dict_sep_bytes} UTF-8 from non-words)",
    ]
    if missing:
        uniq = sorted(set(missing))
        lines.append("")
        lines.append(
            f"   Note: {len(uniq)} message word(s) not found in dictionary (index size above still assumes in-dict words): "
            + ", ".join(repr(w) for w in uniq[:12])
            + (" …" if len(uniq) > 12 else "")
        )
    return "\n".join(lines)


def encode_message(
    parts: List[Tuple[str, str, str]], token_map: Dict[str, int]
) -> Tuple[List[EncodedWord | str], List[str]]:
    encoded: List[EncodedWord | str] = []
    missing: List[str] = []
    for kind, text, case_style in parts:
        if kind == "sep":
            encoded.append(text)
            continue
        canonical = text.lower()
        token = token_map.get(canonical)
        if token is None:
            missing.append(text)
        encoded.append(EncodedWord(token=token, case_style=case_style, original=text))
    return encoded, missing


def ensure_message_words_in_dictionary(
    message_parts: List[Tuple[str, str, str]],
    dictionary_words: List[str],
    path: Path,
) -> None:
    """Ensure all message words exist in the dictionary."""
    existing: Set[str] = set(dictionary_words)
    to_append: List[str] = []

    for kind, text, _case in message_parts:
        if kind != "word":
            continue
        canonical = text.lower()
        if canonical not in existing:
            existing.add(canonical)
            dictionary_words.append(canonical)
            to_append.append(canonical)

    if to_append:
        with path.open("a", encoding="utf-8") as handle:
            for word in to_append:
                handle.write(f"{word}\n")
        update_dictionary_count(path, len(dictionary_words))


def update_dictionary_count(path: Path, count: int) -> None:
    """Rewrite the first line of the dictionary with the new count."""
    with path.open("r+", encoding="utf-8") as handle:
        lines = handle.readlines()
        if lines:
            lines[0] = f"{count}\n"
        else:
            lines = [f"{count}\n"]
        handle.seek(0)
        handle.writelines(lines)
        handle.truncate()


def decode_message(
    encoded: List[EncodedWord | str], reverse_map: Dict[int, str]
) -> Tuple[str, int, List[str]]:
    decoded_parts: List[str] = []
    mismatches = 0
    unknown: List[str] = []

    for item in encoded:
        if isinstance(item, str):
            decoded_parts.append(item)
            continue
        if item.token is None:
            unknown.append(item.original)
            decoded_parts.append(item.original)
            mismatches += 1
            continue
        base_word = reverse_map.get(item.token)
        if base_word is None:
            unknown.append(item.original)
            decoded_parts.append(item.original)
            mismatches += 1
            continue
        adjusted = apply_case(base_word, item.case_style, item.original)
        decoded_parts.append(adjusted)
        if adjusted != item.original:
            mismatches += 1
    return "".join(decoded_parts), mismatches, unknown


# Column legend for table display
COLUMN_LEGEND = [
    "(1) Loop Number",
    "(2) Dictionary Size",
    "(3) Session Timestamp",
    "(4) Encode Dict Time (ms)",
    "(5) Encode Msg Time (ms)",
    "(6) Decode Dict Time (ms)",
    "(7) Decode Msg Time (ms)",
    "(8) Total Time (ms)",
    "(9) Collision Count",
    "(10) Token Value (the)",
    "(11) Verification Result",
    "(12) Word Mismatches",
    "(13) Reconstructed Message",
]

CSV_HEADERS = [
    "Loop Number",
    "Dictionary Size",
    "Session Timestamp",
    "Encode Dict Time (ms)",
    "Encode Msg Time (ms)",
    "Decode Dict Time (ms)",
    "Decode Msg Time (ms)",
    "Total Time (ms)",
    "Collision Count",
    "Token Value (the)",
    "Verification Result",
    "Word Mismatches",
    "Reconstructed Message",
]


def run_round_trip(
    message: str,
    num_loops: int,
    dictionary_path: Path,
    truncation_bits: int,
    hash_type: str = "HMAC-SHA256",
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Tuple[List[RoundTripResult], List[float]]:
    """Run round-trip and return list of results plus averages row."""
    message_parts = tokenize_message(message)
    words = load_dictionary(dictionary_path)

    ensure_message_words_in_dictionary(message_parts, words, dictionary_path)
    dict_count = len(words)

    word_entries: List[Tuple[str, bytes]] = [
        (w, w.encode("utf-8")) for w in words
    ]

    results: List[RoundTripResult] = []

    for loop_idx in range(1, num_loops + 1):
        if progress_callback:
            progress_callback(loop_idx, num_loops)
        overall_start = time.perf_counter()
        session_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        secret_salt = secrets.token_bytes(16)
        hmac_key = session_timestamp.encode("utf-8") + secret_salt

        encode_dict_start = time.perf_counter()
        encode_word_to_token, _, encode_collisions = build_token_maps(
            word_entries, hmac_key, truncation_bits, hash_type
        )
        encode_dict_time = time.perf_counter() - encode_dict_start

        encode_msg_start = time.perf_counter()
        encoded_message, _ = encode_message(message_parts, encode_word_to_token)
        encode_msg_time = time.perf_counter() - encode_msg_start

        token_value_the = encode_word_to_token.get("the")
        encode_word_to_token = {}

        decode_dict_start = time.perf_counter()
        _, decode_token_to_word, _ = build_token_maps(
            word_entries, hmac_key, truncation_bits, hash_type
        )
        decode_dict_time = time.perf_counter() - decode_dict_start

        decode_msg_start = time.perf_counter()
        reconstructed_message, word_mismatches, _ = decode_message(
            encoded_message, decode_token_to_word
        )
        decode_msg_time = time.perf_counter() - decode_msg_start

        total_time = time.perf_counter() - overall_start
        verification_passed = reconstructed_message == message

        results.append(
            RoundTripResult(
                loop_number=loop_idx,
                dictionary_size=dict_count,
                session_timestamp=session_timestamp,
                encode_dict_time_ms=encode_dict_time * 1000,
                encode_msg_time_ms=encode_msg_time * 1000,
                decode_dict_time_ms=decode_dict_time * 1000,
                decode_msg_time_ms=decode_msg_time * 1000,
                total_time_ms=total_time * 1000,
                collision_count=encode_collisions,
                token_value_the=token_value_the,
                verification_result="PASS" if verification_passed else "FAIL",
                word_mismatches=word_mismatches,
                reconstructed_message=reconstructed_message,
            )
        )

    # Compute averages
    n = len(results)
    averages = [
        sum(r.encode_dict_time_ms for r in results) / n,
        sum(r.encode_msg_time_ms for r in results) / n,
        sum(r.decode_dict_time_ms for r in results) / n,
        sum(r.decode_msg_time_ms for r in results) / n,
        sum(r.total_time_ms for r in results) / n,
        sum(r.collision_count for r in results) / n,
        sum(r.token_value_the or 0 for r in results) / n
        if any(r.token_value_the for r in results)
        else 0,
        sum(r.word_mismatches for r in results) / n,
    ]
    return results, averages


def run_collision_sweep(
    dictionary_path: Path,
    bit_widths: List[int],
    loops_per_width: int,
    message: str,
    hash_type: str = "HMAC-SHA256",
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> List[SweepResult]:
    """Run collision tests across bit widths. Measures MESSAGE-WORD collisions
    (collisions among words in the message) — what matters for communications.
    Each session uses a different HMAC key, so same word gets different token across messages."""
    if not message.strip():
        raise ValueError("Message is required for sweep (measures message-word collisions).")
    words = load_dictionary(dictionary_path)
    message_parts = tokenize_message(message)
    ensure_message_words_in_dictionary(message_parts, words, dictionary_path)
    message_words = list(dict.fromkeys(
        p[1].lower() for p in message_parts if p[0] == "word"
    ))
    if not message_words:
        raise ValueError("Message contains no words.")
    word_entries: List[Tuple[str, bytes]] = [(w, w.encode("utf-8")) for w in words]
    m = len(message_words)
    expected_per_bw = {bw: expected_collisions(m, bw) for bw in bit_widths}

    results: List[SweepResult] = []
    for bw in bit_widths:
        collisions_list: List[int] = []
        for loop_idx in range(loops_per_width):
            if progress_callback:
                progress_callback(f"{bw} bits", loop_idx + 1, loops_per_width)
            session_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
            secret_salt = secrets.token_bytes(16)
            hmac_key = session_timestamp.encode("utf-8") + secret_salt
            word_to_token, _, _ = build_token_maps(word_entries, hmac_key, bw, hash_type)
            collision_count = count_message_word_collisions(word_to_token, message_words)
            collisions_list.append(collision_count)

        avg = sum(collisions_list) / len(collisions_list)
        std = statistics.stdev(collisions_list) if len(collisions_list) > 1 else 0.0
        results.append(
            SweepResult(
                bit_width=bw,
                loops=loops_per_width,
                avg_collisions=avg,
                min_collisions=min(collisions_list),
                max_collisions=max(collisions_list),
                expected_collisions=expected_per_bw[bw],
                std_dev=std,
                message_word_count=m,
            )
        )
    return results


def sweep_results_to_table_text(results: List[SweepResult]) -> str:
    """Format sweep results as table."""
    lines: List[str] = []
    lines.append("MESSAGE-WORD COLLISIONS vs BIT WIDTH")
    lines.append("=" * 90)
    lines.append(
        f"Unique message words: {results[0].message_word_count}  |  "
        f"Loops per bit width: {results[0].loops}"
    )
    lines.append("(Collisions among words in your message — what matters for communications)")
    lines.append("")
    lines.append(
        "Bit Width | Loops | Avg Collisions | Min   | Max   | Expected | Std Dev"
    )
    lines.append("-" * 90)
    for r in results:
        lines.append(
            f"{r.bit_width:^9} | {r.loops:^5} | {r.avg_collisions:^14.2f} | "
            f"{r.min_collisions:^5} | {r.max_collisions:^5} | "
            f"{r.expected_collisions:^8.2f} | {r.std_dev:.2f}"
        )
    return "\n".join(lines)


def sweep_results_to_csv_rows(results: List[SweepResult]) -> List[List[str]]:
    """Convert sweep results to CSV rows."""
    headers = [
        "Bit Width", "Loops", "Message Word Count", "Avg Collisions", "Min Collisions", "Max Collisions",
        "Expected Collisions", "Std Dev",
    ]
    rows = [headers]
    for r in results:
        rows.append([
            str(r.bit_width),
            str(r.loops),
            str(r.message_word_count),
            f"{r.avg_collisions:.6f}",
            str(r.min_collisions),
            str(r.max_collisions),
            f"{r.expected_collisions:.6f}",
            f"{r.std_dev:.6f}",
        ])
    return rows


def results_to_table_text(results: List[RoundTripResult], averages: List[float]) -> str:
    """Format results as table with legend."""
    lines: List[str] = []
    lines.append("REFERENCE LEGEND:")
    lines.append("-" * 60)
    for legend in COLUMN_LEGEND:
        lines.append(f"  {legend}")
    lines.append("")
    lines.append("RESULTS TABLE:")
    lines.append("-" * 60)

    # Header row (numbered) - column 3 is 20 chars to fit timestamp
    col_widths = [12, 12, 20, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12]
    headers = ["(1)", "(2)", "(3)", "(4)", "(5)", "(6)", "(7)", "(8)", "(9)", "(10)", "(11)", "(12)", "(13)"]
    lines.append(" | ".join(f"{h:^{w}}" for h, w in zip(headers, col_widths)))

    for r in results:
        token_the_str = str(r.token_value_the) if r.token_value_the is not None else "N/A"
        row = [
            str(r.loop_number),
            str(r.dictionary_size),
            r.session_timestamp[:20] + ".." if len(r.session_timestamp) > 22 else r.session_timestamp,
            f"{r.encode_dict_time_ms:.3f}",
            f"{r.encode_msg_time_ms:.3f}",
            f"{r.decode_dict_time_ms:.3f}",
            f"{r.decode_msg_time_ms:.3f}",
            f"{r.total_time_ms:.3f}",
            str(r.collision_count),
            token_the_str[:10] if len(token_the_str) > 10 else token_the_str,
            r.verification_result,
            str(r.word_mismatches),
            (r.reconstructed_message[:20] + "..") if len(r.reconstructed_message) > 22 else r.reconstructed_message,
        ]
        lines.append(" | ".join(f"{x:^{w}}" for x, w in zip(row, col_widths)))

    if results:
        lines.append("")
        lines.append("AVERAGES:")
        lines.append(
            f"  Encode Dict: {averages[0]:.3f} ms | Encode Msg: {averages[1]:.3f} ms | "
            f"Decode Dict: {averages[2]:.3f} ms | Decode Msg: {averages[3]:.3f} ms"
        )
        lines.append(
            f"  Total: {averages[4]:.3f} ms | Collisions: {averages[5]:.3f} | "
            f"Token(the): {averages[6]:.3f} | Mismatches: {averages[7]:.3f}"
        )

    return "\n".join(lines)


def results_to_csv_rows(results: List[RoundTripResult]) -> List[List[str]]:
    """Convert results to CSV rows with headers in first row.
    Token value (the) is stored as string to prevent Excel scientific notation."""
    rows: List[List[str]] = [CSV_HEADERS]
    for r in results:
        # Use string format with leading apostrophe so Excel treats as text (no scientific notation)
        token_the_str = f"'{r.token_value_the}" if r.token_value_the is not None else ""
        rows.append([
            str(r.loop_number),
            str(r.dictionary_size),
            r.session_timestamp,
            f"{r.encode_dict_time_ms:.6f}",
            f"{r.encode_msg_time_ms:.6f}",
            f"{r.decode_dict_time_ms:.6f}",
            f"{r.decode_msg_time_ms:.6f}",
            f"{r.total_time_ms:.6f}",
            str(r.collision_count),
            token_the_str,
            r.verification_result,
            str(r.word_mismatches),
            r.reconstructed_message,
        ])
    return rows


class TokenRoundTripApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Token Round Trip Encoder/Decoder")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)

        self.dictionary_path = tk.StringVar(value=str(Path("D:\\QuantumShift\\en_US.dic")))
        self.truncation_bits = tk.IntVar(value=48)
        self.num_loops = tk.IntVar(value=10)
        self.message_text: Optional[tk.Text] = None
        self.results_text: Optional[scrolledtext.ScrolledText] = None
        self.last_results: Optional[List[RoundTripResult]] = None
        self.last_averages: Optional[List[float]] = None

        # Bit Width Sweep
        self.sweep_bits_min = tk.IntVar(value=3)
        self.sweep_bits_max = tk.IntVar(value=24)
        self.sweep_bits_step = tk.IntVar(value=1)
        self.sweep_loops = tk.IntVar(value=10)
        self.sweep_results_text: Optional[scrolledtext.ScrolledText] = None
        self.last_sweep_results: Optional[List[SweepResult]] = None

        # Bucket Distribution
        self.bucket_word = tk.StringVar(value="")
        self.bucket_runs = tk.IntVar(value=100)
        self.bucket_bits_var = tk.StringVar(value="8")
        self.bucket_results_text: Optional[scrolledtext.ScrolledText] = None
        self.last_bucket_result: Optional[BucketTestResult] = None

        # Cross-Session Difference
        self.sessdiff_word = tk.StringVar(value="")
        self.sessdiff_pairs = tk.IntVar(value=100)
        self.sessdiff_bits_var = tk.StringVar(value="48")
        self.sessdiff_results_text: Optional[scrolledtext.ScrolledText] = None
        self.last_sessdiff_result: Optional[SessionDiffResult] = None

        # Min Token Distance
        self.mindist_sessions = tk.IntVar(value=100)
        self.mindist_bits_var = tk.StringVar(value="48")
        self.mindist_results_text: Optional[scrolledtext.ScrolledText] = None
        self.last_mindist_result: Optional[MinTokenDistResult] = None

        # Hash function (shared)
        self.hash_type = tk.StringVar(value="HMAC-SHA256")

        # Tokenization Preview
        self.preview_trunc_var = tk.StringVar(value="48")
        self.preview_results_text: Optional[scrolledtext.ScrolledText] = None

        # Message payload size comparison
        self.size_report_text: Optional[scrolledtext.ScrolledText] = None

        # Dictionary prefix collision mapping
        self.dict_coll_word_count = tk.IntVar(value=1000)
        self.dict_coll_bits = tk.IntVar(value=24)
        self.dict_coll_loops = tk.IntVar(value=20)
        self.dict_coll_results_text: Optional[scrolledtext.ScrolledText] = None
        self.dict_coll_birthday_var = tk.StringVar(value="")
        self.dict_coll_passphrase = tk.StringVar(value="")
        self.dict_coll_chain_state = tk.StringVar(value="")
        self.dict_coll_extra = tk.StringVar(value="")
        self.dict_coll_timestamp_each_epoch = tk.BooleanVar(value=True)
        self.dict_coll_salt_each_epoch = tk.BooleanVar(value=True)
        self.last_dict_coll_study: Optional[DictPrefixCollisionStudy] = None

        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # Shared dictionary, hash, and message (top level)
        dict_frame = ttk.Frame(main)
        dict_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(dict_frame, text="Dictionary:").pack(side=tk.LEFT, padx=(0, 5))
        dict_entry = ttk.Entry(dict_frame, textvariable=self.dictionary_path, width=60)
        dict_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(dict_frame, text="Browse...", command=self._browse_dictionary).pack(side=tk.LEFT)

        hash_frame = ttk.Frame(main)
        hash_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(hash_frame, text="Hash:").pack(side=tk.LEFT, padx=(0, 5))
        for opt in HASH_OPTIONS:
            ttk.Radiobutton(hash_frame, text=opt, variable=self.hash_type, value=opt).pack(side=tk.LEFT, padx=(0, 15))

        msg_frame = tk.LabelFrame(
            main,
            text="Test message (required for Round Trip, Sweep, Min Distance, Preview, Message Size)",
            fg="red",
        )
        msg_frame.pack(fill=tk.X, pady=(0, 5), padx=0, ipadx=5, ipady=5)
        self.message_text = scrolledtext.ScrolledText(msg_frame, height=3, width=60, wrap=tk.WORD)
        self.message_text.pack(fill=tk.BOTH, expand=True)
        self.msg_frame = msg_frame

        # Notebook with tabs: 0=RoundTrip, 1=Sweep, 2=Bucket, 3=SessDiff, 4=MinDist, 5=Preview, 6=MessageSize, 7=DictCollisions
        self._tabs_requiring_message = {0, 1, 4, 5, 6}

        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self._notebook = notebook

        # --- Tab 1: Round Trip ---
        round_trip_tab = ttk.Frame(notebook, padding=5)
        notebook.add(round_trip_tab, text="Round Trip")

        inputs_frame = ttk.LabelFrame(round_trip_tab, text="Inputs", padding=10)
        inputs_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(inputs_frame, text="Truncation (bits):").grid(row=0, column=0, sticky=tk.W, pady=2)
        trunc_frame = ttk.Frame(inputs_frame)
        trunc_frame.grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Spinbox(trunc_frame, from_=3, to=128, textvariable=self.truncation_bits, width=8).pack(side=tk.LEFT)
        ttk.Label(trunc_frame, text="(3–128)").pack(side=tk.LEFT, padx=(5, 0))

        ttk.Label(inputs_frame, text="Number of loops:").grid(row=1, column=0, sticky=tk.W, pady=2)
        loop_frame = ttk.Frame(inputs_frame)
        loop_frame.grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Spinbox(loop_frame, from_=1, to=10000, textvariable=self.num_loops, width=8).pack(side=tk.LEFT)
        ttk.Label(loop_frame, text="(1–10000)").pack(side=tk.LEFT, padx=(5, 0))
        inputs_frame.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(round_trip_tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Run Round Trip", command=self._run).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Download CSV", command=self._download_csv).pack(side=tk.LEFT)

        output_frame = ttk.LabelFrame(round_trip_tab, text="Output (Table)", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.results_text = scrolledtext.ScrolledText(
            output_frame, height=16, wrap=tk.NONE, font=("Consolas", 9)
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        hscroll = ttk.Scrollbar(output_frame, orient=tk.HORIZONTAL, command=self.results_text.xview)
        self.results_text.configure(xscrollcommand=hscroll.set)
        hscroll.pack(fill=tk.X)

        # --- Tab 2: Bit Width Sweep ---
        sweep_tab = ttk.Frame(notebook, padding=5)
        notebook.add(sweep_tab, text="Bit Width Sweep")

        sweep_inputs = ttk.LabelFrame(sweep_tab, text="Sweep Parameters", padding=10)
        sweep_inputs.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(sweep_inputs, text="Bit width range:").grid(row=0, column=0, sticky=tk.W, pady=2)
        range_frame = ttk.Frame(sweep_inputs)
        range_frame.grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Spinbox(range_frame, from_=3, to=128, textvariable=self.sweep_bits_min, width=6).pack(side=tk.LEFT)
        ttk.Label(range_frame, text="to").pack(side=tk.LEFT, padx=5)
        ttk.Spinbox(range_frame, from_=3, to=128, textvariable=self.sweep_bits_max, width=6).pack(side=tk.LEFT)
        ttk.Label(range_frame, text="step").pack(side=tk.LEFT, padx=5)
        ttk.Spinbox(range_frame, from_=1, to=64, textvariable=self.sweep_bits_step, width=6).pack(side=tk.LEFT)

        ttk.Label(sweep_inputs, text="Loops per bit width:").grid(row=1, column=0, sticky=tk.W, pady=2)
        sweep_loop_frame = ttk.Frame(sweep_inputs)
        sweep_loop_frame.grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Spinbox(sweep_loop_frame, from_=1, to=500, textvariable=self.sweep_loops, width=8).pack(side=tk.LEFT)
        ttk.Label(sweep_loop_frame, text="(e.g. 10–50)").pack(side=tk.LEFT, padx=(5, 0))
        sweep_inputs.columnconfigure(1, weight=1)

        sweep_btn_frame = ttk.Frame(sweep_tab)
        sweep_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(sweep_btn_frame, text="Run Bit Width Sweep", command=self._run_sweep).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sweep_btn_frame, text="Download Sweep CSV", command=self._download_sweep_csv).pack(side=tk.LEFT, padx=(0, 5))
        if HAS_MATPLOTLIB:
            ttk.Button(sweep_btn_frame, text="Show Plot", command=self._show_sweep_plot).pack(side=tk.LEFT)

        sweep_output = ttk.LabelFrame(sweep_tab, text="Message-Word Collisions vs Bit Width", padding=10)
        sweep_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.sweep_results_text = scrolledtext.ScrolledText(
            sweep_output, height=16, wrap=tk.NONE, font=("Consolas", 9)
        )
        self.sweep_results_text.pack(fill=tk.BOTH, expand=True)

        # --- Tab 3: Bucket Distribution ---
        bucket_tab = ttk.Frame(notebook, padding=5)
        notebook.add(bucket_tab, text="Bucket Distribution")

        bucket_inputs = ttk.LabelFrame(bucket_tab, text="Distribution Test (HMAC uniformity)", padding=10)
        bucket_inputs.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(bucket_inputs, text="Word:").grid(row=0, column=0, sticky=tk.W, pady=2)
        bucket_word_entry = ttk.Entry(bucket_inputs, textvariable=self.bucket_word, width=30)
        bucket_word_entry.grid(row=0, column=1, sticky=tk.W, pady=2)

        ttk.Label(bucket_inputs, text="Number of runs:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(bucket_inputs, from_=1, to=100000, textvariable=self.bucket_runs, width=10).grid(row=1, column=1, sticky=tk.W, pady=2)

        ttk.Label(bucket_inputs, text="Truncation (buckets):").grid(row=2, column=0, sticky=tk.W, pady=2)
        bucket_bits_combo = ttk.Combobox(
            bucket_inputs, textvariable=self.bucket_bits_var, width=10,
            values=["8", "16", "32", "64", "128"], state="readonly"
        )
        bucket_bits_combo.grid(row=2, column=1, sticky=tk.W, pady=2)
        bucket_bits_combo.set("8")
        ttk.Label(bucket_inputs, text="(8→256, 16→65K, 32→4B, 64→18Q, 128 buckets)").grid(row=2, column=2, sticky=tk.W, padx=(5, 0), pady=2)
        bucket_inputs.columnconfigure(1, weight=1)

        bucket_btn_frame = ttk.Frame(bucket_tab)
        bucket_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(bucket_btn_frame, text="Run Bucket Test", command=self._run_bucket_test).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(bucket_btn_frame, text="Download Bucket CSV", command=self._download_bucket_csv).pack(side=tk.LEFT)

        bucket_output = ttk.LabelFrame(bucket_tab, text="Bucket Index vs Token Count", padding=10)
        bucket_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.bucket_results_text = scrolledtext.ScrolledText(
            bucket_output, height=12, wrap=tk.NONE, font=("Consolas", 9)
        )
        self.bucket_results_text.pack(fill=tk.BOTH, expand=True)
        bucket_hscroll = ttk.Scrollbar(bucket_output, orient=tk.HORIZONTAL, command=self.bucket_results_text.xview)
        self.bucket_results_text.configure(xscrollcommand=bucket_hscroll.set)
        bucket_hscroll.pack(fill=tk.X)

        # --- Tab 4: Cross-Session Difference ---
        sessdiff_tab = ttk.Frame(notebook, padding=5)
        notebook.add(sessdiff_tab, text="Cross-Session Difference")

        sessdiff_inputs = ttk.LabelFrame(sessdiff_tab, text="Session Difference Test (avalanche / independence)", padding=10)
        sessdiff_inputs.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(sessdiff_inputs, text="Word:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(sessdiff_inputs, textvariable=self.sessdiff_word, width=30).grid(row=0, column=1, sticky=tk.W, pady=2)

        ttk.Label(sessdiff_inputs, text="Number of pairs:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(sessdiff_inputs, from_=1, to=10000, textvariable=self.sessdiff_pairs, width=10).grid(row=1, column=1, sticky=tk.W, pady=2)

        ttk.Label(sessdiff_inputs, text="Truncation (bits):").grid(row=2, column=0, sticky=tk.W, pady=2)
        sessdiff_bits_combo = ttk.Combobox(
            sessdiff_inputs, textvariable=self.sessdiff_bits_var, width=10,
            values=["8", "16", "32", "48", "64", "128"], state="readonly"
        )
        sessdiff_bits_combo.grid(row=2, column=1, sticky=tk.W, pady=2)
        sessdiff_bits_combo.set("48")
        ttk.Label(sessdiff_inputs, text="(for token Hamming distance)").grid(row=2, column=2, sticky=tk.W, padx=(5, 0), pady=2)
        sessdiff_inputs.columnconfigure(1, weight=1)

        sessdiff_btn_frame = ttk.Frame(sessdiff_tab)
        sessdiff_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(sessdiff_btn_frame, text="Run Session Difference Test", command=self._run_sessdiff_test).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sessdiff_btn_frame, text="Download CSV", command=self._download_sessdiff_csv).pack(side=tk.LEFT)

        sessdiff_output = ttk.LabelFrame(sessdiff_tab, text="Token vs HMAC Difference (session to session)", padding=10)
        sessdiff_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.sessdiff_results_text = scrolledtext.ScrolledText(
            sessdiff_output, height=14, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.sessdiff_results_text.pack(fill=tk.BOTH, expand=True)

        # --- Tab 5: Min Token Distance ---
        mindist_tab = ttk.Frame(notebook, padding=5)
        notebook.add(mindist_tab, text="Min Token Distance")

        mindist_inputs = ttk.LabelFrame(mindist_tab, text="Distance to Collision (uses message above)", padding=10)
        mindist_inputs.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(mindist_inputs, text="Number of sessions:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(mindist_inputs, from_=1, to=10000, textvariable=self.mindist_sessions, width=10).grid(row=0, column=1, sticky=tk.W, pady=2)

        ttk.Label(mindist_inputs, text="Truncation (bits):").grid(row=1, column=0, sticky=tk.W, pady=2)
        mindist_bits_combo = ttk.Combobox(
            mindist_inputs, textvariable=self.mindist_bits_var, width=10,
            values=[str(b) for b in range(4, 129, 4)], state="readonly"
        )
        mindist_bits_combo.grid(row=1, column=1, sticky=tk.W, pady=2)
        mindist_bits_combo.set("48")
        ttk.Label(mindist_inputs, text="(min Hamming distance between any two message-word tokens)").grid(row=1, column=2, sticky=tk.W, padx=(5, 0), pady=2)
        mindist_inputs.columnconfigure(1, weight=1)

        mindist_btn_frame = ttk.Frame(mindist_tab)
        mindist_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(mindist_btn_frame, text="Run Min Distance Test", command=self._run_mindist_test).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(mindist_btn_frame, text="Download CSV", command=self._download_mindist_csv).pack(side=tk.LEFT)

        mindist_output = ttk.LabelFrame(mindist_tab, text="Session Number vs Min Distance Between Tokens", padding=10)
        mindist_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.mindist_results_text = scrolledtext.ScrolledText(
            mindist_output, height=14, wrap=tk.NONE, font=("Consolas", 9)
        )
        self.mindist_results_text.pack(fill=tk.BOTH, expand=True)
        mindist_hscroll = ttk.Scrollbar(mindist_output, orient=tk.HORIZONTAL, command=self.mindist_results_text.xview)
        self.mindist_results_text.configure(xscrollcommand=mindist_hscroll.set)
        mindist_hscroll.pack(fill=tk.X)

        # --- Tab 6: Tokenization Preview ---
        preview_tab = ttk.Frame(notebook, padding=5)
        notebook.add(preview_tab, text="Tokenization Preview")

        preview_inputs = ttk.LabelFrame(preview_tab, text="Behind the Scenes (uses message above)", padding=10)
        preview_inputs.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(preview_inputs, text="Truncation (bits):").grid(row=0, column=0, sticky=tk.W, pady=2)
        preview_trunc_combo = ttk.Combobox(
            preview_inputs, textvariable=self.preview_trunc_var, width=10,
            values=[str(b) for b in range(4, 129, 4)], state="readonly"
        )
        preview_trunc_combo.grid(row=0, column=1, sticky=tk.W, pady=2)
        preview_trunc_combo.set("48")

        ttk.Button(preview_tab, text="Generate Tokenization", command=self._run_preview).pack(anchor=tk.W, pady=5)

        preview_output = ttk.LabelFrame(preview_tab, text="Session: Timestamp, Salt, Word → Token", padding=10)
        preview_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.preview_results_text = scrolledtext.ScrolledText(
            preview_output, height=16, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.preview_results_text.pack(fill=tk.BOTH, expand=True)

        # --- Message Size tab (notebook index 6) ---
        size_tab = ttk.Frame(notebook, padding=5)
        notebook.add(size_tab, text="Message Size")

        size_intro = ttk.Label(
            size_tab,
            text=(
                "Compares payload size for the message above: "
                f"{HMAC_WIRE_BITS}-bit token per word/separator piece, UTF-8 per character, "
                "and dictionary index per word plus UTF-8 for non-word segments."
            ),
            wraplength=820,
        )
        size_intro.pack(anchor=tk.W, pady=(0, 8))

        size_btn = ttk.Frame(size_tab)
        size_btn.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(size_btn, text="Calculate", command=self._run_message_size).pack(side=tk.LEFT)

        size_output = ttk.LabelFrame(size_tab, text="Payload bytes and piece counts (no transmission overhead)", padding=10)
        size_output.pack(fill=tk.BOTH, expand=True)
        self.size_report_text = scrolledtext.ScrolledText(
            size_output, height=22, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.size_report_text.pack(fill=tk.BOTH, expand=True)

        # --- Tab: Dictionary prefix collisions ---
        dict_coll_tab = ttk.Frame(notebook, padding=5)
        notebook.add(dict_coll_tab, text="Dictionary Collisions")

        dict_coll_intro = ttk.Label(
            dict_coll_tab,
            text=(
                "Uses the first N words from the dictionary (file order). Each run line is one epoch: "
                "the HMAC key is built from your passphrase / chain state / extras, plus the epoch index, "
                "and (by default) a new UTC timestamp and random salt so the collision “geometry” changes "
                "when any binding changes — same idea as a per–message-set key from chain + time + secret."
            ),
            wraplength=820,
        )
        dict_coll_intro.pack(anchor=tk.W, pady=(0, 8))

        dict_coll_inputs = ttk.LabelFrame(dict_coll_tab, text="Parameters", padding=10)
        dict_coll_inputs.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(dict_coll_inputs, text="Words from dictionary (first N, file order):").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        ttk.Spinbox(
            dict_coll_inputs, from_=2, to=500000, textvariable=self.dict_coll_word_count, width=12
        ).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(dict_coll_inputs, text="(2 … dictionary size)").grid(
            row=0, column=2, sticky=tk.W, padx=(5, 0), pady=2
        )

        ttk.Label(dict_coll_inputs, text="Truncation (bits):").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(
            dict_coll_inputs, from_=3, to=128, textvariable=self.dict_coll_bits, width=12
        ).grid(row=1, column=1, sticky=tk.W, pady=2)

        ttk.Label(dict_coll_inputs, text="Epochs (runs):").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(
            dict_coll_inputs, from_=1, to=10000, textvariable=self.dict_coll_loops, width=12
        ).grid(row=2, column=1, sticky=tk.W, pady=2)
        ttk.Label(dict_coll_inputs, text="(one collision map per epoch)").grid(
            row=2, column=2, sticky=tk.W, padx=(5, 0), pady=2
        )

        epoch_key = ttk.LabelFrame(dict_coll_inputs, text="Epoch HMAC key material (concatenated, UTF-8)", padding=6)
        epoch_key.grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=(6, 4))
        epoch_key.columnconfigure(1, weight=1)

        ttk.Label(epoch_key, text="Passphrase / shared secret:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(epoch_key, textvariable=self.dict_coll_passphrase, width=56, show="*").grid(
            row=0, column=1, columnspan=2, sticky=tk.EW, pady=2
        )

        ttk.Label(epoch_key, text="Chain state:").grid(row=1, column=0, sticky=tk.NW, pady=2)
        ttk.Entry(epoch_key, textvariable=self.dict_coll_chain_state, width=56).grid(
            row=1, column=1, columnspan=2, sticky=tk.EW, pady=2
        )

        ttk.Label(epoch_key, text="Extra (e.g. label, counter):").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(epoch_key, textvariable=self.dict_coll_extra, width=56).grid(
            row=2, column=1, columnspan=2, sticky=tk.EW, pady=2
        )

        toggles = ttk.Frame(epoch_key)
        toggles.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(4, 0))
        ttk.Checkbutton(
            toggles,
            text="Append fresh UTC timestamp each epoch",
            variable=self.dict_coll_timestamp_each_epoch,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            toggles,
            text="Append random 16-byte salt each epoch",
            variable=self.dict_coll_salt_each_epoch,
        ).pack(side=tk.LEFT)

        self.dict_coll_birthday_label = ttk.Label(
            dict_coll_inputs,
            textvariable=self.dict_coll_birthday_var,
            wraplength=780,
        )
        self.dict_coll_birthday_label.grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=(8, 0))
        dict_coll_inputs.columnconfigure(1, weight=1)

        dict_coll_btn = ttk.Frame(dict_coll_tab)
        dict_coll_btn.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(dict_coll_btn, text="Run collision mapping", command=self._run_dict_coll_study).pack(
            side=tk.LEFT, padx=(0, 5)
        )
        if HAS_MATPLOTLIB:
            ttk.Button(dict_coll_btn, text="Show plot", command=self._show_dict_coll_plot).pack(side=tk.LEFT)

        dict_coll_output = ttk.LabelFrame(dict_coll_tab, text="Collision pairs per epoch", padding=10)
        dict_coll_output.pack(fill=tk.BOTH, expand=True)
        self.dict_coll_results_text = scrolledtext.ScrolledText(
            dict_coll_output, height=18, wrap=tk.NONE, font=("Consolas", 9)
        )
        self.dict_coll_results_text.pack(fill=tk.BOTH, expand=True)
        dict_coll_hscroll = ttk.Scrollbar(
            dict_coll_output, orient=tk.HORIZONTAL, command=self.dict_coll_results_text.xview
        )
        self.dict_coll_results_text.configure(xscrollcommand=dict_coll_hscroll.set)
        dict_coll_hscroll.pack(fill=tk.X)

        self._update_dict_coll_birthday_display()
        self.dict_coll_word_count.trace_add("write", lambda *_: self._update_dict_coll_birthday_display())
        self.dict_coll_bits.trace_add("write", lambda *_: self._update_dict_coll_birthday_display())

    def _update_dict_coll_birthday_display(self) -> None:
        """Show E[collision pairs] ≈ n² / 2^(b+1) when n and b are valid."""
        try:
            n = int(self.dict_coll_word_count.get())
            b = int(self.dict_coll_bits.get())
        except (tk.TclError, ValueError):
            self.dict_coll_birthday_var.set("")
            return
        if n < 2 or b < 3 or b > 128:
            self.dict_coll_birthday_var.set("")
            return
        exp = expected_collisions(n, b)
        self.dict_coll_birthday_var.set(
            f"Expected unordered collision pairs (birthday bound): {exp:.6g}  "
            f"(n = {n} words, b = {b} truncated bits, 2^{b} buckets)"
        )

    def _on_tab_changed(self, event: tk.Event) -> None:
        """Update message label color: red if required for current tab, black otherwise."""
        try:
            idx = self._notebook.index(self._notebook.select())
            required = idx in self._tabs_requiring_message
            self.msg_frame.config(foreground="red" if required else "black")
        except Exception:
            pass

    def _browse_dictionary(self):
        path = filedialog.askopenfilename(
            title="Select Dictionary File",
            filetypes=[("Dictionary files", "*.dic"), ("All files", "*.*")],
            initialdir=str(Path(self.dictionary_path.get()).parent),
        )
        if path:
            self.dictionary_path.set(path)

    def _validate_inputs(self) -> Optional[str]:
        msg = self.message_text.get("1.0", tk.END).strip()
        if not msg:
            return "Please enter a message."
        try:
            bits = int(self.truncation_bits.get())
            if not (3 <= bits <= 128):
                return "Truncation must be between 3 and 128 bits."
        except tk.TclError:
            return "Truncation must be a valid number (3–128)."
        try:
            loops = int(self.num_loops.get())
            if not (1 <= loops <= 10000):
                return "Loops must be between 1 and 10000."
        except tk.TclError:
            return "Loops must be a valid number (1–10000)."
        path = Path(self.dictionary_path.get())
        if not path.exists():
            return f"Dictionary file not found: {path}"
        return None

    def _run(self):
        err = self._validate_inputs()
        if err:
            messagebox.showerror("Validation Error", err)
            return

        msg = self.message_text.get("1.0", tk.END).strip()
        num_loops = int(self.num_loops.get())
        dict_path = Path(self.dictionary_path.get())
        trunc_bits = int(self.truncation_bits.get())

        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "Running... please wait.\n")
        self.root.update()

        def on_progress(current: int, total: int) -> None:
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, f"Processing loop {current} of {total}...\n")
            self.root.update()

        try:
            t0 = time.perf_counter()
            results, averages = run_round_trip(
                msg, num_loops, dict_path, trunc_bits,
                hash_type=self.hash_type.get(), progress_callback=on_progress
            )
            elapsed = time.perf_counter() - t0
            self.last_results = results
            self.last_averages = averages
            table = results_to_table_text(results, averages)
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, f"Total run time: {format_elapsed(elapsed)}\n\n")
            self.results_text.insert(tk.END, table)
        except Exception as e:
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, f"Error: {e}")
            self.last_results = None
            self.last_averages = None

    def _download_csv(self):
        if not self.last_results:
            messagebox.showinfo("No Data", "Run a round trip first to generate data for CSV download.")
            return

        path = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            rows = results_to_csv_rows(self.last_results)
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            messagebox.showinfo("Saved", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _validate_sweep_inputs(self) -> Optional[str]:
        msg = self.message_text.get("1.0", tk.END).strip()
        if not msg:
            return "Message is required for sweep (measures collisions among message words)."
        path = Path(self.dictionary_path.get())
        if not path.exists():
            return f"Dictionary file not found: {path}"
        try:
            min_b = int(self.sweep_bits_min.get())
            max_b = int(self.sweep_bits_max.get())
            step = int(self.sweep_bits_step.get())
            if not (3 <= min_b <= 128 and 3 <= max_b <= 128):
                return "Bit width must be between 3 and 128."
            if min_b > max_b:
                return "Min bit width must be ≤ max."
            if step < 1:
                return "Step must be ≥ 1."
        except tk.TclError:
            return "Invalid bit width or step values."
        try:
            loops = int(self.sweep_loops.get())
            if not (1 <= loops <= 500):
                return "Loops per bit width must be 1–500."
        except tk.TclError:
            return "Invalid loops value."
        return None

    def _run_sweep(self):
        err = self._validate_sweep_inputs()
        if err:
            messagebox.showerror("Validation Error", err)
            return

        dict_path = Path(self.dictionary_path.get())
        min_b = int(self.sweep_bits_min.get())
        max_b = int(self.sweep_bits_max.get())
        step = int(self.sweep_bits_step.get())
        loops = int(self.sweep_loops.get())

        bit_widths = list(range(min_b, max_b + 1, step))
        if not bit_widths:
            messagebox.showerror("Error", "No bit widths in range.")
            return

        self.sweep_results_text.delete("1.0", tk.END)
        self.sweep_results_text.insert(tk.END, f"Running sweep: {len(bit_widths)} bit widths × {loops} loops...\n")
        self.root.update()

        def on_progress(bw_str: str, current: int, total: int) -> None:
            self.sweep_results_text.delete("1.0", tk.END)
            self.sweep_results_text.insert(
                tk.END, f"Sweep: {bw_str} — loop {current} of {total}...\n"
            )
            self.root.update()

        try:
            t0 = time.perf_counter()
            msg = self.message_text.get("1.0", tk.END).strip()
            results = run_collision_sweep(
                dict_path, bit_widths, loops, message=msg,
                hash_type=self.hash_type.get(), progress_callback=on_progress
            )
            elapsed = time.perf_counter() - t0
            self.last_sweep_results = results
            table = sweep_results_to_table_text(results)
            self.sweep_results_text.delete("1.0", tk.END)
            self.sweep_results_text.insert(tk.END, f"Total run time: {format_elapsed(elapsed)}\n\n")
            self.sweep_results_text.insert(tk.END, table)
        except Exception as e:
            self.sweep_results_text.delete("1.0", tk.END)
            self.sweep_results_text.insert(tk.END, f"Error: {e}")
            self.last_sweep_results = None

    def _run_bucket_test(self):
        word = self.bucket_word.get().strip()
        if not word:
            messagebox.showerror("Validation Error", "Please enter a word.")
            return
        try:
            num_runs = int(self.bucket_runs.get())
            if not (1 <= num_runs <= 100000):
                messagebox.showerror("Validation Error", "Runs must be 1–100000.")
                return
        except tk.TclError:
            messagebox.showerror("Validation Error", "Invalid runs value.")
            return
        bits_str = self.bucket_bits_var.get()
        if bits_str not in ("8", "16", "32", "64", "128"):
            messagebox.showerror("Validation Error", "Truncation must be 8, 16, 32, 64, or 128.")
            return
        truncation_bits = int(bits_str)

        self.bucket_results_text.delete("1.0", tk.END)
        self.bucket_results_text.insert(tk.END, f"Running {num_runs} runs for '{word}' at {truncation_bits} bits...\n")
        self.root.update()

        def on_progress(current: int, total: int) -> None:
            self.bucket_results_text.delete("1.0", tk.END)
            self.bucket_results_text.insert(tk.END, f"Run {current} of {total}...\n")
            self.root.update()

        try:
            counts, elapsed = run_bucket_distribution(
                word, num_runs, truncation_bits,
                hash_type=self.hash_type.get(), progress_callback=on_progress
            )
            num_buckets = len(counts)
            stats = compute_bucket_stats(counts, num_runs, num_buckets)
            self.last_bucket_result = BucketTestResult(
                word=word, num_runs=num_runs, truncation_bits=truncation_bits,
                num_buckets=num_buckets, counts=counts, elapsed=elapsed, stats=stats,
            )
            output = format_bucket_output(counts, truncation_bits, num_runs, stats)
            self.bucket_results_text.delete("1.0", tk.END)
            self.bucket_results_text.insert(tk.END, f"Total run time: {format_elapsed(elapsed)}\n")
            self.bucket_results_text.insert(tk.END, f"Word: '{word}' | Runs: {num_runs} | Buckets: {num_buckets}\n\n")
            self.bucket_results_text.insert(tk.END, output)
        except Exception as e:
            self.bucket_results_text.delete("1.0", tk.END)
            self.bucket_results_text.insert(tk.END, f"Error: {e}")
            self.last_bucket_result = None

    def _download_bucket_csv(self):
        if not self.last_bucket_result:
            messagebox.showinfo("No Data", "Run a bucket test first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Bucket CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            rows = bucket_result_to_csv_rows(self.last_bucket_result)
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            messagebox.showinfo("Saved", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _run_sessdiff_test(self):
        word = self.sessdiff_word.get().strip()
        if not word:
            messagebox.showerror("Validation Error", "Please enter a word.")
            return
        try:
            num_pairs = int(self.sessdiff_pairs.get())
            if not (1 <= num_pairs <= 10000):
                messagebox.showerror("Validation Error", "Pairs must be 1–10000.")
                return
        except tk.TclError:
            messagebox.showerror("Validation Error", "Invalid pairs value.")
            return
        bits_str = self.sessdiff_bits_var.get()
        if bits_str not in ("8", "16", "32", "48", "64", "128"):
            messagebox.showerror("Validation Error", "Truncation must be 8, 16, 32, 48, 64, or 128.")
            return
        truncation_bits = int(bits_str)

        self.sessdiff_results_text.delete("1.0", tk.END)
        self.sessdiff_results_text.insert(tk.END, f"Running {num_pairs} session pairs for '{word}'...\n")
        self.root.update()

        def on_progress(current: int, total: int) -> None:
            self.sessdiff_results_text.delete("1.0", tk.END)
            self.sessdiff_results_text.insert(tk.END, f"Pair {current} of {total}...\n")
            self.root.update()

        try:
            result = run_session_difference(
                word, num_pairs, truncation_bits,
                hash_type=self.hash_type.get(), progress_callback=on_progress
            )
            self.last_sessdiff_result = result
            expected_full = 128
            expected_token = truncation_bits / 2
            output = [
                f"Total run time: {format_elapsed(result.elapsed)}",
                "",
                f"Word: '{word}' | Pairs: {num_pairs} | Truncation: {truncation_bits} bits",
                "",
                "FULL HMAC (256 bits) — Hamming distance between sessions:",
                f"  Expected: ~{expected_full} bits (avalanche: ~50% differ)",
                f"  Mean:     {result.hamming_full_mean:.2f}",
                f"  Std Dev:  {result.hamming_full_std:.2f}",
                f"  Min:      {result.hamming_full_min} | Max: {result.hamming_full_max}",
                "",
                f"TRUNCATED TOKEN ({truncation_bits} bits) — Hamming distance between sessions:",
                f"  Expected: ~{expected_token:.0f} bits (~50% differ)",
                f"  Mean:     {result.hamming_token_mean:.2f}",
                f"  Std Dev:  {result.hamming_token_std:.2f}",
                f"  Min:      {result.hamming_token_min} | Max: {result.hamming_token_max}",
                "",
                "Interpretation: Values near expected = good avalanche/independence across sessions.",
            ]
            self.sessdiff_results_text.delete("1.0", tk.END)
            self.sessdiff_results_text.insert(tk.END, "\n".join(output))
        except Exception as e:
            self.sessdiff_results_text.delete("1.0", tk.END)
            self.sessdiff_results_text.insert(tk.END, f"Error: {e}")
            self.last_sessdiff_result = None

    def _download_sessdiff_csv(self):
        if not self.last_sessdiff_result:
            messagebox.showinfo("No Data", "Run a session difference test first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Session Difference CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            rows = session_diff_result_to_csv_rows(self.last_sessdiff_result)
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            messagebox.showinfo("Saved", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _run_mindist_test(self):
        msg = self.message_text.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showerror("Validation Error", "Message is required (uses message words).")
            return
        try:
            num_sessions = int(self.mindist_sessions.get())
            if not (1 <= num_sessions <= 10000):
                messagebox.showerror("Validation Error", "Sessions must be 1–10000.")
                return
        except tk.TclError:
            messagebox.showerror("Validation Error", "Invalid sessions value.")
            return
        bits_str = self.mindist_bits_var.get()
        try:
            truncation_bits = int(bits_str)
            if truncation_bits < 4 or truncation_bits > 128 or truncation_bits % 4 != 0:
                messagebox.showerror("Validation Error", "Truncation must be a multiple of 4 (4–128).")
                return
        except ValueError:
            messagebox.showerror("Validation Error", "Truncation must be a multiple of 4 (4–128).")
            return

        self.mindist_results_text.delete("1.0", tk.END)
        self.mindist_results_text.insert(tk.END, "Running min token distance test...\n")
        self.root.update()

        def on_progress(current: int, total: int) -> None:
            self.mindist_results_text.delete("1.0", tk.END)
            self.mindist_results_text.insert(tk.END, f"Session {current} of {total}...\n")
            self.root.update()

        try:
            result = run_min_token_distance(
                msg, num_sessions, truncation_bits,
                hash_type=self.hash_type.get(), progress_callback=on_progress
            )
            self.last_mindist_result = result
            collisions = sum(1 for _, d in result.session_min_distances if d == 0)
            dists = [d for _, d in result.session_min_distances]
            output = [
                f"Total run time: {format_elapsed(result.elapsed)}",
                "",
                f"Message words: {len(result.message_words)} | Sessions: {num_sessions} | Truncation: {truncation_bits} bits",
                f"Collisions (min_dist=0): {collisions} / {num_sessions}",
                "",
                "Session | MinDistance  (0 = collision, higher = farther from collision)",
                "-" * 50,
            ]
            col_w = max(6, len(str(num_sessions)))
            for sess_num, min_dist in result.session_min_distances:
                output.append(f"{sess_num:^{col_w}} | {min_dist}")
            output.extend([
                "",
                f"Summary: Mean min distance = {statistics.mean(dists):.2f} | "
                f"Min = {min(dists)} | Max = {max(dists)}",
            ])
            self.mindist_results_text.delete("1.0", tk.END)
            self.mindist_results_text.insert(tk.END, "\n".join(output))
        except ValueError as e:
            self.mindist_results_text.delete("1.0", tk.END)
            self.mindist_results_text.insert(tk.END, f"Error: {e}")
            self.last_mindist_result = None
        except Exception as e:
            self.mindist_results_text.delete("1.0", tk.END)
            self.mindist_results_text.insert(tk.END, f"Error: {e}")
            self.last_mindist_result = None

    def _download_mindist_csv(self):
        if not self.last_mindist_result:
            messagebox.showinfo("No Data", "Run a min token distance test first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Min Token Distance CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            rows = min_token_dist_result_to_csv_rows(self.last_mindist_result)
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            messagebox.showinfo("Saved", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _run_preview(self):
        msg = self.message_text.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showerror("Validation Error", "Message is required.")
            return
        try:
            trunc = int(self.preview_trunc_var.get())
            if trunc < 4 or trunc > 128 or trunc % 4 != 0:
                messagebox.showerror("Validation Error", "Truncation must be a multiple of 4 (4–128).")
                return
        except ValueError:
            messagebox.showerror("Validation Error", "Invalid truncation value.")
            return
        hash_type = self.hash_type.get()
        try:
            timestamp, salt_hex, pairs = generate_tokenization_preview(msg, trunc, hash_type)
            lines = [
                "TOKENIZATION PREVIEW (what's being evaluated behind the scenes)",
                "=" * 60,
                f"Hash: {hash_type} | Truncation: {trunc} bits",
                "",
                f"Timestamp: {timestamp}",
                f"Salt (hex): {salt_hex}",
                "",
                "Word → Token",
                "-" * 40,
            ]
            for word, token in pairs:
                lines.append(f"  {word:>20} → {token}")
            if not pairs:
                lines.append("  (no words in message)")
            self.preview_results_text.delete("1.0", tk.END)
            self.preview_results_text.insert(tk.END, "\n".join(lines))
        except ValueError as e:
            self.preview_results_text.delete("1.0", tk.END)
            self.preview_results_text.insert(tk.END, f"Error: {e}")
        except Exception as e:
            self.preview_results_text.delete("1.0", tk.END)
            self.preview_results_text.insert(tk.END, f"Error: {e}")

    def _run_message_size(self):
        assert self.size_report_text is not None
        msg = self.message_text.get("1.0", tk.END).strip()
        path = Path(self.dictionary_path.get())
        if not path.exists():
            self.size_report_text.delete("1.0", tk.END)
            self.size_report_text.insert(tk.END, f"Dictionary file not found:\n{path}")
            return
        try:
            words = load_dictionary(path)
            report = format_message_payload_size_report(msg, words, hmac_wire_bits=HMAC_WIRE_BITS)
            self.size_report_text.delete("1.0", tk.END)
            self.size_report_text.insert(tk.END, report)
        except Exception as e:
            self.size_report_text.delete("1.0", tk.END)
            self.size_report_text.insert(tk.END, f"Error: {e}")

    def _download_sweep_csv(self):
        if not self.last_sweep_results:
            messagebox.showinfo("No Data", "Run a bit width sweep first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Sweep CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            rows = sweep_results_to_csv_rows(self.last_sweep_results)
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            messagebox.showinfo("Saved", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _show_sweep_plot(self):
        if not self.last_sweep_results:
            messagebox.showinfo("No Data", "Run a bit width sweep first.")
            return
        if not HAS_MATPLOTLIB:
            messagebox.showinfo("Not Available", "matplotlib is not installed.")
            return
        results = self.last_sweep_results
        bits = [r.bit_width for r in results]
        avg = [r.avg_collisions for r in results]
        expected = [r.expected_collisions for r in results]
        win = tk.Toplevel(self.root)
        win.title("Message-Word Collisions vs Bit Width")
        fig = Figure(figsize=(8, 5))
        ax = fig.add_subplot(111)
        ax.plot(bits, avg, "b-o", label="Observed (avg)", markersize=4)
        ax.plot(bits, expected, "r--", label="Expected (birthday bound)")
        ax.set_xlabel("Bit Width")
        ax.set_ylabel("Collisions (among message words)")
        ax.set_title(f"Message-Word Collisions vs Truncation ({results[0].message_word_count} unique words)")
        ax.legend()
        ax.grid(True, alpha=0.3)
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _validate_dict_coll_inputs(self) -> Optional[str]:
        path = Path(self.dictionary_path.get())
        if not path.exists():
            return f"Dictionary file not found: {path}"
        try:
            n = int(self.dict_coll_word_count.get())
            if n < 2:
                return "Word count must be at least 2."
        except tk.TclError:
            return "Word count must be a valid number."
        try:
            b = int(self.dict_coll_bits.get())
            if not (3 <= b <= 128):
                return "Truncation must be between 3 and 128 bits."
        except tk.TclError:
            return "Truncation must be a valid number."
        try:
            loops = int(self.dict_coll_loops.get())
            if not (1 <= loops <= 10000):
                return "Loops must be between 1 and 10000."
        except tk.TclError:
            return "Loops must be a valid number."
        return None

    def _run_dict_coll_study(self) -> None:
        assert self.dict_coll_results_text is not None
        err = self._validate_dict_coll_inputs()
        if err:
            messagebox.showerror("Validation Error", err)
            return
        dict_path = Path(self.dictionary_path.get())
        n = int(self.dict_coll_word_count.get())
        b = int(self.dict_coll_bits.get())
        loops = int(self.dict_coll_loops.get())

        self.dict_coll_results_text.delete("1.0", tk.END)
        self.dict_coll_results_text.insert(
            tk.END, f"Running {loops} epoch(s), first {n} words at {b} bits...\n"
        )
        self.root.update()

        def on_progress(current: int, total: int) -> None:
            self.dict_coll_results_text.delete("1.0", tk.END)
            self.dict_coll_results_text.insert(
                tk.END, f"Epoch {current} of {total} (first {n} dictionary words, {b} bits)...\n"
            )
            self.root.update()

        try:
            study = run_dictionary_prefix_collision_study(
                dict_path,
                n,
                b,
                loops,
                hash_type=self.hash_type.get(),
                passphrase=self.dict_coll_passphrase.get(),
                chain_state=self.dict_coll_chain_state.get(),
                extra=self.dict_coll_extra.get(),
                include_timestamp_per_epoch=self.dict_coll_timestamp_each_epoch.get(),
                include_random_salt_per_epoch=self.dict_coll_salt_each_epoch.get(),
                progress_callback=on_progress,
            )
            self.last_dict_coll_study = study
            pair_counts = [lr.pair_count for lr in study.loop_results]
            lines: List[str] = [
                "DICTIONARY PREFIX COLLISION MAPPING",
                "=" * 72,
                f"Hash: {self.hash_type.get()}",
                f"Epoch key binding: {study.epoch_key_summary}",
                f"First N words (file order): N = {study.n_dictionary_words}",
                f"Truncation: {study.truncation_bits} bits  |  Epochs: {study.loops}",
                f"Expected collision pairs (birthday): {study.expected_pair_count:.6g}",
                f"Observed pair counts — min: {min(pair_counts)}, max: {max(pair_counts)}, "
                f"mean: {statistics.mean(pair_counts):.4f}"
                + (
                    f", stdev: {statistics.stdev(pair_counts):.4f}"
                    if len(pair_counts) > 1
                    else ""
                ),
                f"Elapsed: {format_elapsed(study.elapsed)}",
                "",
            ]
            for lr in study.loop_results:
                lines.append(f"--- Epoch {lr.loop_number} — {lr.pair_count} pair(s) ---")
                if not lr.pairs:
                    lines.append("  (no collisions)")
                else:
                    for a, w in lr.pairs:
                        lines.append(f"  {a!r}  <->  {w!r}")
                lines.append("")
            self.dict_coll_results_text.delete("1.0", tk.END)
            self.dict_coll_results_text.insert(tk.END, "\n".join(lines))
        except Exception as e:
            self.dict_coll_results_text.delete("1.0", tk.END)
            self.dict_coll_results_text.insert(tk.END, f"Error: {e}")
            self.last_dict_coll_study = None

    def _show_dict_coll_plot(self) -> None:
        if not self.last_dict_coll_study:
            messagebox.showinfo("No Data", "Run dictionary collision mapping first.")
            return
        if not HAS_MATPLOTLIB:
            messagebox.showinfo("Not Available", "matplotlib is not installed.")
            return
        study = self.last_dict_coll_study
        xs = [lr.loop_number for lr in study.loop_results]
        ys = [lr.pair_count for lr in study.loop_results]
        exp = study.expected_pair_count
        win = tk.Toplevel(self.root)
        win.title("Dictionary prefix — collision pairs per loop")
        fig = Figure(figsize=(8, 5))
        ax = fig.add_subplot(111)
        ax.bar(xs, ys, color="steelblue", alpha=0.85, label="Observed pairs")
        ax.axhline(exp, color="crimson", linestyle="--", linewidth=1.5, label="Expected (birthday)")
        ax.set_xlabel("Epoch index")
        ax.set_ylabel("Unordered collision pairs")
        ax.set_title(
            f"First {study.n_dictionary_words} words | {study.truncation_bits} bits | "
            f"{study.loops} epoch(s)"
        )
        ax.legend()
        ax.grid(True, axis="y", alpha=0.3)
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = TokenRoundTripApp()
    app.run()
