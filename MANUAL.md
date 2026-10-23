# Token Round Trip Encoder/Decoder

User's manual for `token_roundtrip-mod.py`.

This is a desktop program. It turns words into short keyed-hash tokens, then checks how well those tokens round-trip, how often they collide, and how evenly they spread. Every control described below is a field, spin box, drop-down, check box, or button in the window. There are no command-line arguments.

## Start the program

Requirements:

- Python 3 with Tk (the standard library `tkinter` module). On Windows this is included with the official Python installer.
- A dictionary text file. See [Dictionary file](#dictionary-file).

Optional packages change what the window offers:

| Package | What you get |
| --- | --- |
| `matplotlib` | **Show Plot** on Bit Width Sweep and **Show plot** on Dictionary Collisions |
| `scipy` | Chi-squared p-value on the Bucket Distribution tab |
| `pycryptodome` | The **KMAC256** hash choice |

Install the optional pieces if you want them:

```text
pip install matplotlib scipy pycryptodome
```

From the folder that contains the script:

```text
python token_roundtrip-mod.py
```

The window title is **Token Round Trip Encoder/Decoder**.

## Shared controls

These sit above the tabs and apply to every test that uses them.

### Dictionary

| Control | Default | What to enter |
| --- | --- | --- |
| **Dictionary** | `D:\QuantumShift\en_US.dic` | Full path to a dictionary file |
| **Browse...** | — | Opens a file picker (`.dic` files, or any file) |

Change the path before you run a tab that reads the dictionary: Round Trip, Bit Width Sweep, Message Size, and Dictionary Collisions.

**Round Trip** and **Bit Width Sweep** write to this file. They append any message word that is missing, then rewrite the count on the first line. Point these tests at a copy of the dictionary if you want the original left unchanged.

### Hash

Radio buttons. The default is **HMAC-SHA256**.

| Choice | When it appears |
| --- | --- |
| HMAC-SHA256 | Always |
| HMAC-SHA512 | Always |
| BLAKE2b | Always |
| KMAC256 | Only if `pycryptodome` is installed |

The selected hash is used by Round Trip, Bit Width Sweep, Bucket Distribution, Cross-Session Difference, Min Token Distance, Tokenization Preview, and Dictionary Collisions. Message Size does not hash; it only counts bytes.

BLAKE2b accepts a key of at most 64 bytes. Session keys (timestamp plus a 16-byte salt) stay under that limit. On Dictionary Collisions, a long passphrase, chain state, or extra field can push the epoch key past 64 bytes and BLAKE2b will fail. Shorten those fields, or pick another hash.

### Test message

A multi-line box labeled **Test message**. The label is red on tabs that require it and black on tabs that ignore it.

Required on:

- Round Trip
- Bit Width Sweep
- Min Token Distance
- Tokenization Preview
- Message Size

Ignored on Bucket Distribution, Cross-Session Difference, and Dictionary Collisions. Those tabs have their own word or dictionary-prefix inputs.

How the message is split:

- A **word** is a run of letters `A–Z`, `a–z`, and apostrophes (`'`).
- Everything else (spaces, punctuation, digits) is a **separator** and is kept as literal text.
- Words are compared in lowercase. On decode, case is restored as ALL CAPS, Title Case, lowercase, or the original mixed spelling.
- Repeated words count once when a test talks about unique message words.

Example: `The cat's mat.` becomes the words `the`, `cat's`, `mat`, plus the separators ` ` and `.`.

## Tabs

### Round Trip

Encodes the message with a fresh session key, decodes it with the same key, and reports whether the text comes back. Each loop builds tokens for **every word in the dictionary**, so a large dictionary is slow. Raise **Number of loops** only after a single loop finishes in a time you can accept.

| Input | Default | Allowed values |
| --- | --- | --- |
| Truncation (bits) | 48 | 3–128 |
| Number of loops | 10 | 1–10000 |
| Test message | (empty) | At least one character after trimming spaces |
| Dictionary | path above | File must exist |
| Hash | HMAC-SHA256 | Any listed hash |

**Run Round Trip** starts the test. **Download CSV** saves the last successful run. Run the test before downloading; otherwise the program tells you there is no data.

Truncation is how many low bits of the hash become the token. Fewer bits means a smaller token and more collisions across the whole dictionary. More bits means fewer collisions and a larger integer.

Each loop uses a new UTC timestamp and a new 16-byte random salt as the key, so the same word gets a different token every loop.

The table columns are:

| Column | Meaning |
| --- | --- |
| (1) Loop Number | 1 … number of loops |
| (2) Dictionary Size | Word count after any missing message words were appended |
| (3) Session Timestamp | UTC time used in that loop’s key (`YYYYMMDDHHMMSSffffff`) |
| (4) Encode Dict Time (ms) | Time to hash the dictionary into tokens |
| (5) Encode Msg Time (ms) | Time to replace message words with tokens |
| (6) Decode Dict Time (ms) | Time to build the token-to-word map |
| (7) Decode Msg Time (ms) | Time to rebuild the message |
| (8) Total Time (ms) | Whole loop |
| (9) Collision Count | Dictionary words whose token was already taken by a different word |
| (10) Token Value (the) | Token for the dictionary word `the`, or N/A if `the` is absent |
| (11) Verification Result | `PASS` when the reconstructed text matches the message you typed |
| (12) Word Mismatches | Words that did not come back as typed (unknown token or case mismatch) |
| (13) Reconstructed Message | Decoded text (the on-screen table truncates long messages; the CSV has the full text) |

An averages row follows the table. In the CSV, the token for `the` is stored with a leading apostrophe so spreadsheets keep it as text.

### Bit Width Sweep

Measures collisions **among the unique words in the test message** while you vary the token width. This is the collision count that matters for sending one message. It is a different count from column (9) on Round Trip, which counts collisions across the whole dictionary.

The sweep still hashes the full dictionary each loop, and it appends missing message words the same way Round Trip does.

| Input | Default | Allowed values |
| --- | --- | --- |
| Bit width range, first box | 3 | 3–128, and this value must be less than or equal to the second box |
| Bit width range, second box | 24 | 3–128 |
| step | 1 | 1–64 |
| Loops per bit width | 10 | 1–500 |
| Test message | (empty) | Must contain at least one word |
| Dictionary | path above | File must exist |
| Hash | HMAC-SHA256 | Any listed hash |

Example: min `8`, max `24`, step `4` runs widths 8, 12, 16, 20, and 24.

**Run Bit Width Sweep** fills the table: bit width, loops, average collisions, min, max, the birthday-bound expectation `n² / 2^(b+1)` (`n` = unique message words, `b` = bit width), and standard deviation.

**Download Sweep CSV** saves the last sweep.

**Show Plot** (only with `matplotlib`) draws observed average collisions and the birthday-bound line. Run a sweep first.

### Bucket Distribution

Hashes one word many times, each time with a new timestamp and salt, and counts which truncated token (bucket) it lands in. This checks whether the hash looks uniform. It does not use the test message or the dictionary.

| Input | Default | Allowed values |
| --- | --- | --- |
| Word | (empty) | Any non-blank text. The whole field is one string; it is not split into words. |
| Number of runs | 100 | 1–100000 |
| Truncation (buckets) | 8 | 8, 16, 32, 64, or 128 |
| Hash | HMAC-SHA256 | Any listed hash |

Bucket count is `2` raised to the truncation:

| Bits | Buckets |
| --- | --- |
| 8 | 256 |
| 16 | 65,536 |
| 32 | about 4 billion |
| 64 | far beyond what this program can store |
| 128 | far beyond what this program can store |

Use **8** for a first look. **16** is usable and slower. **32**, **64**, and **128** try to allocate one counter per bucket and will run out of memory. The on-screen chart bins anything above 256 buckets into 256 columns. The CSV lists individual buckets and stops after 100,000 rows.

**Run Bucket Test** prints mean, standard deviation, min, max, empty buckets, and chi-squared. If `scipy` is installed it also prints a p-value; a high p-value is consistent with a uniform spread.

**Download Bucket CSV** saves the last test.

### Cross-Session Difference

Takes one word, builds two independent session keys, and measures how many bits differ. It repeats that for the number of pairs you set. This checks avalanche: about half the bits should flip when the key changes. It does not use the test message or the dictionary.

| Input | Default | Allowed values |
| --- | --- | --- |
| Word | (empty) | Any non-blank text (one string, not split) |
| Number of pairs | 100 | 1–10000 |
| Truncation (bits) | 48 | 8, 16, 32, 48, 64, or 128 |
| Hash | HMAC-SHA256 | Any listed hash |

The report has two blocks:

- **Full HMAC (256 bits).** Expected Hamming distance is about 128 (half of 256). The program always compares the first 256 bits of the digest, including for HMAC-SHA512 and BLAKE2b.
- **Truncated token.** Expected distance is about half the truncation you chose (24 when truncation is 48).

**Run Session Difference Test** prints mean, standard deviation, min, and max for both blocks. **Download CSV** saves the last summary (one row of statistics, not every pair).

### Min Token Distance

For each session, hashes the unique words in the **test message** and reports the smallest Hamming distance between any two of those tokens. Distance `0` means two different message words landed on the same token (a collision). Larger distances mean the closest pair is farther apart. This tab hashes only the message words, and it does not modify the dictionary.

| Input | Default | Allowed values |
| --- | --- | --- |
| Number of sessions | 100 | 1–10000 |
| Truncation (bits) | 48 | Multiples of 4 from 4 through 128 (4, 8, 12, … 128) |
| Test message | (empty) | At least two unique words |
| Hash | HMAC-SHA256 | Any listed hash |

**Run Min Distance Test** lists `Session | MinDistance`, then how many sessions collided, plus mean, min, and max distance. **Download CSV** saves a short header (word count, sessions, bits, collision count, elapsed time) and one row per session.

### Tokenization Preview

Shows one session of the encoding used behind the other message tests: timestamp, salt in hex, and each unique lowercased word with its truncated token. It does not read or write the dictionary, and it does not decode.

| Input | Default | Allowed values |
| --- | --- | --- |
| Truncation (bits) | 48 | Multiples of 4 from 4 through 128 |
| Test message | (empty) | Required. A message with no words prints `(no words in message)`. |
| Hash | HMAC-SHA256 | Any listed hash |

**Generate Tokenization** runs once. Click it again for a new timestamp, salt, and set of tokens. There is no CSV button on this tab.

### Message Size

Compares three ways of sizing the **test message**. It reads the dictionary and does not modify it. Hash and truncation controls on other tabs do not affect this report. The token model always uses a fixed 128-bit (16-byte) value per piece.

**Calculate** is the only control on the tab. The dictionary file must exist. An empty message is allowed and reports zero pieces.

The report contains:

1. **Session tokens.** One 16-byte value for every word piece and every separator piece.
2. **Plain characters.** Number of Unicode code points, and the UTF-8 byte length of the whole message.
3. **Dictionary index plus literal non-words.** Each word piece costs enough bytes to store an index into this dictionary. Each separator is stored as its own UTF-8 bytes. Words that are not in the dictionary are listed (up to 12); their index size is still counted as if they were in the file.

### Dictionary Collisions

Hashes the **first N words of the dictionary file** (file order, after the loader cleans each line) and lists which words share a truncated token. Each epoch gets its own key, so the colliding pairs change when the key material changes. This tab does not use the test message and does not modify the dictionary.

| Input | Default | Allowed values |
| --- | --- | --- |
| Words from dictionary (first N, file order) | 1000 | At least 2, and no more than the number of words in the file. The spin box allows up to 500000; the run fails if N is larger than the file. |
| Truncation (bits) | 24 | 3–128 |
| Epochs (runs) | 20 | 1–10000 |
| Passphrase / shared secret | (empty) | Any text. Characters are hidden. Stored and hashed as UTF-8. |
| Chain state | (empty) | Any text, UTF-8. A new chain state produces a new collision map. |
| Extra (e.g. label, counter) | (empty) | Any text, UTF-8. Use it as a label or counter you want bound into the key. |
| Append fresh UTC timestamp each epoch | checked | Uncheck to keep the timestamp out of the key. |
| Append random 16-byte salt each epoch | checked | Uncheck to keep the random salt out of the key. |
| Hash | HMAC-SHA256 | Any listed hash |
| Dictionary | path above | File must exist |

The line under the inputs updates as you edit N and the bit width. It shows the birthday bound for unordered collision pairs: `n² / 2^(b+1)`.

Key construction, in order, joined by an ASCII record separator:

1. The fixed label `QS-EPOCH-v1`
2. Passphrase
3. Chain state
4. Extra
5. The epoch index (`loop=1`, `loop=2`, …)
6. A fresh UTC timestamp, if that box is checked
7. 16 random bytes, if that box is checked

With both boxes checked (the default), every epoch differs even when the three text fields stay the same. Uncheck both boxes when you want epochs to differ only by the loop index, so you can see the effect of editing the passphrase, chain state, or extra field and running again.

**Run collision mapping** prints, for each epoch, the number of colliding pairs and the word pairs themselves (`word` ↔ `word`). A summary at the top gives min, max, mean, and (when there is more than one epoch) standard deviation of the pair counts, plus the expected birthday value.

**Show plot** (only with `matplotlib`) draws pair count per epoch and a horizontal line at the expected value. Run the mapping first. There is no CSV button on this tab.

Large N with a small bit width produces many pairs and a long listing. Start with the defaults (1000 words, 24 bits, 20 epochs) and increase N or decrease bits only when you want more collisions to inspect.

## Dictionary file

Plain UTF-8 text, one entry per line, in the style of a Hunspell `.dic` file:

```text
3
apple
banana/S
The
```

- The first line is a count. The loader skips it and does not treat it as a word.
- Blank lines are skipped.
- A slash and anything after it are removed (`banana/S` becomes `banana`).
- Words are stored in lowercase (`The` becomes `the`).
- File order is the order Dictionary Collisions uses for “first N words,” and the order Message Size uses for dictionary indexes. The first occurrence of a repeated word keeps the index.

After a Round Trip or Bit Width Sweep that had to add words, the first line is rewritten to the new word count and the new words are appended, one per line, in lowercase.

## Saving results

CSV buttons open a save dialog. Choose a path ending in `.csv`. Buttons and what they require:

| Button | Tab | Requires |
| --- | --- | --- |
| Download CSV | Round Trip | A finished round trip |
| Download Sweep CSV | Bit Width Sweep | A finished sweep |
| Download Bucket CSV | Bucket Distribution | A finished bucket test |
| Download CSV | Cross-Session Difference | A finished session-difference test |
| Download CSV | Min Token Distance | A finished min-distance test |

Tokenization Preview, Message Size, and Dictionary Collisions keep their results in the window only.

## What to change first

1. Set **Dictionary** to a real file on your machine. Use a copy if you will run Round Trip or Bit Width Sweep.
2. Type a short sentence in **Test message**.
3. Leave **Hash** on HMAC-SHA256.
4. On **Round Trip**, leave truncation at 48 and set loops to `1`. Click **Run Round Trip**.
5. Open **Tokenization Preview** and click **Generate Tokenization** to see the word-to-token list for that same message.
6. Open **Bit Width Sweep** with a narrow range (for example 8 to 16, step 2, 5 loops) before widening it.
7. On **Bucket Distribution**, keep truncation at 8.
8. On **Dictionary Collisions**, leave the defaults, then change passphrase, chain state, or extra and run again to see the collision pairs move.
