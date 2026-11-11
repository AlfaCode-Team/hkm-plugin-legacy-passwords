# Changelog

All notable changes to `hkm-plugin-legacy-passwords` are documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **First release: verify a password against a hash another system wrote, then
  replace it on login.** Solves `password.legacy`. Needs `crypto.services` and
  nothing else — no database table, no migration, no routes, no PHP extension
  beyond `hash` and `openssl`.

- **Nine schemes, each pinned by a known-answer test from a DIFFERENT
  implementation.** bcrypt and Argon2 through `password_verify`; crypt(3)
  (`$1$`, `$5$`, `$6$`, DES) through `crypt()`; phpass (`$P$` WordPress and
  Drupal 6, `$H$` phpBB3); Django's PBKDF2; RFC 7914 scrypt; Firebase's modified
  scrypt; salted or unsalted digests; and plaintext. The oracles were Python's
  and Node's scrypt, Node's AES-256-CTR, Python's `hashlib`, `openssl passwd`,
  Appwrite's own `PHPass` implementation run locally, and PHP's `password_hash`.
  A vector produced by the code under test proves nothing — it is a test that
  cannot fail.

- **RFC 7914 scrypt in pure PHP, because PHP has none.** The three things that
  look like one are not: `ext-scrypt` is a PECL extension almost nobody
  installs (Appwrite's own scrypt importer requires it and throws without it);
  `sodium_crypto_pwhash_scryptsalsa208sha256()` takes `opslimit`/`memlimit`
  rather than N, r and p and insists on a 32-byte salt, so it cannot reproduce
  a Node or Firebase hash — checked, the signature on PHP 8.5 is
  `(int $length, string $password, string $salt, int $opslimit, int $memlimit)`;
  and `hash('scrypt', …)` does not exist.

- **The scrypt cost is MEASURED, not estimated: 1.58 s** at N=16384, r=8, p=1 —
  Firebase's defaults — on PHP 8.5.12, Apple Silicon, OPcache loaded with JIT
  disabled. OpenSSL's C implementation does the same derivation in 45 ms, a gap
  of about 35×. That is fine here because of an asymmetry worth stating: A
  LEGACY HASH CAN ONLY EVER BE VERIFIED ONCE PER USER. Re-hashing needs the
  plaintext, the plaintext exists only during a login, and that login is the one
  that replaces it — so there is no bulk migration to be slow at, for any
  password scheme ever designed. A test asserts the figure stays inside a wide
  band, so a factor-of-ten regression fails the suite instead of rotting into a
  stale comment.

- **The Salsa20/8 core is unrolled over sixteen locals, and the reason is
  measured.** The array-indexed version of the same function is **2.8× slower**
  over 60,000 calls — and that measurement charges the unrolled side with
  reflection overhead it does not pay in production, so the real gap is wider.
  At 524,288 calls per Firebase verification that is one and a half seconds
  against about four and a half. The array version was also kept long enough to
  confirm byte-identical output, making it a second, differently shaped
  implementation agreeing with this one.

- **No "try them all" mode, and there will not be one.** Verifying a 32-character
  hex digest against `md5(pw)`, then `md5(salt.pw)`, then `md5(pw.salt)` gives an
  attacker four chances at a collision instead of one, and a collision in the
  WEAKEST scheme on the list authenticates a user whose password was stored
  under the strongest — the security of the set becomes that of its worst
  member. It is also the kind of mistake that looks like a feature in a
  migration tool, because it makes an import "just work" against an undocumented
  database right up to the first forged login. Unambiguous prefixes are
  detected; bare digests are DECLARED, by whoever read the old application's
  source.

- **The salted digest family, which Appwrite cannot read at all.** Its `md5` and
  `sha` importers hash the password and nothing else — `md5($value)`,
  `hash('sha256', $value)` — so a salted column, which is the overwhelming
  majority of real legacy tables, has no path through them. Here the algorithm,
  the salt, its PLACEMENT (before or after the password), the encoding and a
  bounded round count are all first-class. The salt's position cannot be
  recovered from a digest at any cost, so it is declared and the README says to
  read the old login code.

- **`rounds` re-feeds hex by default, because `md5(md5($x))` is ambiguous across
  languages.** PHP's inner call returns the 32-character hex string and the
  outer hashes that; most other languages feed the 16 raw bytes. The two share
  no output bytes. The salt is applied in ROUND ONE ONLY — vBulletin's
  `md5(md5($password) . $salt)` applies it in round two and is explicitly NOT
  supported, because every extra position doubles a configuration surface whose
  wrong setting fails silently.

- **The digest algorithm list is an allowlist.** `hash()` offers sixty
  algorithms including `crc32b` and `xxh64`; a 32-bit checksum has collisions
  anybody can find in milliseconds, so a column holding one is not an
  authentication check. MD5 is on the list precisely because real tables hold
  MD5 and the alternative is those users being unable to log in at all.

- **Firebase's construction, with the three details that are each a way to get
  it wrong.** The salt and separator are CONCATENATED as the scrypt salt (the
  separator is not a delimiter — `Bw==` is one `0x07` byte); only the FIRST 32
  bytes of the 64-byte derived key are used as the AES key; and the password is
  the KEY while the signer key is the PLAINTEXT, so the output's length follows
  the signer key rather than any digest size.

- **An empty Firebase signer key is refused at construction, because it is a
  total authentication bypass.** Measured: `openssl_encrypt('', 'aes-256-ctr',
  …)` returns the EMPTY STRING rather than false, so with no signer key every
  password would hash to `''`, and `hash_equals('', '')` is true — every
  password would verify for every user, reached by forgetting one field of the
  export.

- **`fromExport()` decodes strictly.** Lenient `base64_decode()` ignores
  characters it does not recognise and returns something plausible for almost
  any input, so a field mangled by a line break would decode to a shorter, wrong
  byte string and fail for every user with nothing to explain it.

- **Work-factor ceilings, checked BEFORE the work is spent.** An import file from
  the system being migrated away from is not trusted input, and one row
  containing `$2y$31$…` is a valid bcrypt hash with 2^31 rounds — hours of CPU
  per verification. Planting it costs nothing, it passes every format check
  because it IS valid, and from then on every login attempt against that account
  occupies a PHP worker until the request times out. A test asserts the refusal
  is fast, because a test that only checked the verdict would pass just as
  happily after hours.

- **Malformed is reported separately from "wrong password".** Both look
  identical from outside, but one is one person mistyping and the other is a
  broken import locking out an entire population — and collapsing them is how a
  broken import stays invisible until support notices that everybody "forgot" at
  once. `suggestsMisconfiguration()` is what a caller routes on, and it is true
  for every refusal except `WrongPassword`.

- **An empty stored value is refused before anything else.** A null or blank
  password column is ordinary in an import, and several schemes would otherwise
  verify against it — `hash_equals('', '')` is true, so a plaintext or digest
  credential over an empty column would authenticate an empty password.

- **Plaintext is supported and off by default.** A plaintext password column is
  a real thing real schemas have, and refusing to read one does not make those
  passwords safer — it makes migrating off them harder, which is the opposite of
  the goal. It has to be enabled deliberately, and it is refused before any
  comparison happens rather than after.

- **crypt(3)'s `rounds=` field is handled.** `$6$rounds=5000$salt$hash` is an
  ordinary hash any `/etc/shadow` or Dovecot export may contain, and a pattern
  that ignored the field would read `rounds=5000` as the salt, measure the wrong
  hash length and reject the row as malformed — for every user whose hash
  carried it, which on some systems is all of them. An ABSENT field is not
  unlimited either: the schemes default to 1,000 (`$1$`) and 5,000
  (`$5$`/`$6$`), so treating it as unbounded would have refused every ordinary
  crypt hash in existence.

- **`legacy:inspect`, the command that prevents the expensive failure.** An
  import of 50,000 users with the salt placement declared the wrong way round
  produces 50,000 rows that look perfect and verify nothing; the fix costs one
  command against one account whose password is known. The password is read from
  STDIN and never from `argv` — an argument is visible to every other process
  through `ps` and is written into the shell history — and
  `AbstractCommand::ask()` is not used because it ECHOES.

- **No `make()` for any legacy scheme, so nothing in a project can reach for MD5
  by accident.** `upgrade()` delegates to the application's own `HashingPort`
  with the application's own cost; a second opinion here would mean a project
  that moved to Argon2 silently getting bcrypt for every migrated user.

- **Exactly one `hash_equals` in the plugin.** Every algorithm class recomputes
  and returns a string; none of them compares. One line to get constant-time
  right, and one line to review — rather than nine comparisons, one of which
  somebody eventually writes as `===` because it reads more naturally.

### Fixed during development

- **A hand-rolled Argon2 PHC parser was added, after a WRONG claim was corrected
  rather than shipped.** The first version of this file asserted that
  `password_get_info()` reports PHP's configured defaults instead of an Argon2
  hash's declared parameters, making the memory ceiling decorative. That was
  based on a test whose hash declared `m=65536` — which is also PHP's default,
  so the experiment could not distinguish "parsed" from "defaulted". Re-measured
  with non-default values: it DOES read the declared `m`, `t` and `p` correctly.

  The parser stayed, for the narrower reasons that survive scrutiny:
  `password_get_info()` recognises Argon2 by PREFIX ALONE and needs neither a
  salt nor a hash to be present (`$argon2id$` is reported as a valid hash), and
  for an unparseable parameter field it silently substitutes PHP's defaults
  (`m=zzz` reads back as 65536). So it cannot tell a complete hash from a
  truncated column, and a ceiling consulting it for a garbled hash compares a
  number from the server's configuration rather than from the hash. A test now
  asserts all three behaviours positively, so the record is right.

- **`argon2d` is reported UNSUPPORTED rather than MALFORMED.** PHP exposes only
  argon2i and argon2id, and `password_get_info()` returns `algo => null` for a
  perfectly valid argon2d hash. Leaning on that answer called a good hash
  corrupt and would have sent an operator hunting an import bug that did not
  exist.

- **A config constructor that would have thrown on every construction.** The
  clamps were written against PROMOTED readonly properties, which PHP forbids
  reassigning — `Cannot modify readonly property`. Verified directly, then
  rewritten with declared properties and plain parameters, which is what lets
  the normalisation live in the one place both named constructors must pass
  through.

- **A claim about integer overflow was C's behaviour, not PHP's.** A comment and
  a test asserted that `128 * r * N` with a large N wraps NEGATIVE and sails
  past the memory ceiling, making the float arithmetic load-bearing. PHP
  PROMOTES TO FLOAT on integer overflow rather than wrapping: measured,
  `128 * 8 * (1 << 60)` is `1.18e21`. The integer form would have been correct
  too. The comment now says so and the test records what actually happens, so
  the next reader does not inherit the wrong model.

- **A docblock described a `normalise()` method that did not exist**, and another
  described a fallback the Provider did not have. The first was corrected to
  describe what the code does; the second was made true by making `HashingPort`
  genuinely optional on the CLI path, so the diagnostic command registers even
  in a project that bound the port only per request — a command that refused to
  appear would be hidden at exactly the moment an import is going wrong.

- **A `scrypt()` docblock described comparing the stored digest against all
  three encodings in turn**, which is precisely the sniffing this plugin
  refuses to do elsewhere. The encoding is now DECLARED on
  `ScryptParameters`, like every other property of a bare scheme.

- **Two test expectations were wrong, not the code.** phpass's `itoa64` alphabet
  begins `.`, `/`, `0`, so the digits are offset by two and `'5'` lands on index
  7 — 128 iterations, and exactly the lower bound the implementation accepts,
  which makes it a better test than the 256 originally asserted. And a
  `$P$J` vector at 2^21 iterations sits ABOVE the shipped default iteration
  ceiling, so the shipped default genuinely refuses something rather than being
  a number nothing reaches.

- **An XML comment containing `--`** (from a quoted command-line flag) made
  `phpunit.xml` unparseable, aborting the whole suite before a single test ran.

- **`legacy:inspect` misreported argon2d, and only RUNNING it found that.** The
  command showed "This build can verify it: yes" and "Work factor: unreadable"
  for an `$argon2d$` hash. Both were wrong: the support check consulted
  `supported()`, which answers for Argon2 as a FAMILY, and the work factor came
  from `password_get_info()`, which returns an empty options array for the one
  Argon2 variant PHP cannot verify. So the command recommended verifying a hash
  it could not verify, and called perfectly legible parameters unreadable. Both
  now go through `Argon2Hash`, and the command gained twenty tests that execute
  it through `BufferIO` — reading it had not found this.

- **The STDIN seam was made injectable so the `--verify` path could be tested at
  all.** Without it the only testable half of the command was the half that
  prints a table, and the half an operator actually acts on — whether a password
  matches — would have shipped having never run.

- **A guard that reported the WRONG VERDICT, found by a revert check.** The
  digest length check lived inside `checkDigest()` and returned `false`, which
  the caller turned into `WrongPassword` — the exact outcome the check's own
  comment said it existed to prevent. So removing it changed nothing observable,
  the suite stayed green, and a guard that reported the wrong thing was
  indistinguishable from dead code.

  It is now CHECK 3a in `decide()`, it produces `MalformedHash`, and it covers
  all three bare families rather than only digests — for scrypt the stored
  length follows the declared output length and encoding, and for Firebase it
  follows the SIGNER KEY, because AES-CTR is a stream cipher and the ciphertext
  is exactly as long as its plaintext. That matters operationally: a truncated
  column or a misdeclared algorithm affects every row of that shape, so
  reported as "wrong password" it looks like a population who all forgot, and
  reported as malformed it reaches an operator. Nine tests pin it, including
  one asserting that a right-length digest which simply does not match is still
  `WrongPassword` — without that, the distinction would collapse rather than
  hold.

- **Five more guards were found UNREACHABLE by construction, and kept.** Each
  is now documented at the line with what makes it unreachable and why it stays,
  rather than being left to look load-bearing: `hash_equals` over `===` (the two
  differ only in timing, which no unit test can observe); crypt(3)'s `*0` guard
  and `matches()`'s `=== ''` arm (CHECK 1 and CHECK 3 already refuse the inputs,
  but both failure modes would be a TOTAL authentication bypass, so three lines
  is cheap); the Argon2 cost source (equivalent to `password_get_info()` today
  only because CHECK 3 parses with the same class — probed across six parameter
  sets, including an integer-overflowing `m=99999999999999999999`, and they
  agree every time); and the bcrypt cost fallback (a ceiling that fails OPEN on
  malformed input is decorative for exactly the input it exists to stop).

- **A docblock claimed the Salsa20/8 core runs `2 × p × N × r` times.** It is
  `4 × p × N × r`: ROMix calls BlockMix N times in each of its two loops, and
  BlockMix makes 2r calls. Counted by instrumenting a copy of the class rather
  than re-deriving the arithmetic — 64, 8192 and 65536 calls for three
  parameter sets, all matching 4pNr. The quoted figure of 524,288 for Firebase's
  parameters was right; the formula beside it was not.

### Notes

- **No real Firebase, Django, WordPress or phpBB export has been imported.** The
  constructions are pinned by known-answer tests against independent
  implementations; no live system's data has been through them.
- **`legacy:inspect` has never been run.** It is wired and lints clean; nothing
  has executed it. Code that has never run has not been tested.
- **One build only**: PHP 8.5.12 with Argon2i/Argon2id compiled in, all three
  crypt(3) variants present, and OpenSSL offering aes-256-ctr. The `supported()`
  reporting for a build missing any of those is reasoned about, not exercised.
- **No timing analysis was done.** `hash_equals` is used everywhere a digest is
  compared, and that it is constant-time is PHP's claim rather than a
  measurement made here.
- **Drupal 7 (`$S$`) and MySQL's `PASSWORD()` are deliberately absent**, because
  nothing on this machine could say whether an implementation of them was
  correct — and the only alternative was to write the algorithm from memory and
  let the test assert whatever the code produced, which is a test that cannot
  fail guarding a path that gates logging in. Both constructions are recorded in
  the README; adding either needs one real hash of a known password.
- **libsodium's `$7$` is absent** even though it needs no implementation — one
  `sodium_crypto_pwhash_scryptsalsa208sha256_str_verify()` call — because a
  system new enough to use libsodium's password API is not one this plugin
  exists to migrate off.
