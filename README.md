# hkm-plugin-legacy-passwords

Verify a password against a hash **some other system wrote**, so users can be
migrated without being asked to reset.

Solves `password.legacy`. No database table, no migration, no routes. Requires
`crypto.services` and nothing else.

```php
// In the login path, when the stored hash is not one your hasher produced.
$credential = $legacy->detect($row['password'])
    ?? LegacyCredential::digest($row['password'], $digestParameters);

$verdict = $legacy->verify($password, $credential);

if (!$verdict->verified) {
    if ($verdict->suggestsMisconfiguration()) {
        // A POPULATION cannot log in, not one person. This needs a human.
        $logger->error($verdict->logLine());
    }

    return null;                       // one generic failure to the user
}

// The ONLY moment the plaintext exists. Take it.
$users->replacePassword($row['id'], $legacy->upgrade($password));
```

---

## The one thing to understand first

**A legacy hash can only ever be replaced during a login.** Re-hashing needs the
plaintext; the plaintext only exists while someone is typing it; the login that
verifies the old hash is the login that must write the new one.

There is no batch job that can do this — not for these schemes, not for bcrypt,
not for any password scheme ever designed. So `LegacyVerdict::mustUpgrade()` is
true for **every** success, with no condition attached, and skipping it means
paying the legacy cost on every future login forever. For the scrypt path that
is a measured 1.58 seconds, per login, indefinitely.

---

## What it verifies

| Scheme | Form | Family | Verified against |
|---|---|---|---|
| bcrypt | `$2$` `$2a$` `$2b$` `$2x$` `$2y$` | self-describing | PHP's `password_verify` |
| Argon2 | `$argon2i$` `$argon2id$` | self-describing | PHP's `password_verify` |
| crypt(3) | `$1$` `$5$` `$6$`, DES | self-describing | `openssl passwd -1/-5/-6` |
| phpass | `$P$` (WordPress, Drupal 6), `$H$` (phpBB3) | self-describing | Appwrite's own `PHPass`, run locally |
| PBKDF2 | `pbkdf2_sha256$…` (Django) | self-describing | Python's `hashlib.pbkdf2_hmac` |
| scrypt | RFC 7914, any N/r/p | **declared** | Python's **and** Node's scrypt |
| Firebase | modified scrypt + AES-256-CTR | **declared** | Node, end to end |
| digests | md5/sha1/sha2/sha3/ripemd/whirlpool, salted or not | **declared** | Python's `hashlib` |
| plaintext | the password itself | **declared** | — (off by default) |

**No extension is required.** scrypt is implemented here in pure PHP, because
PHP has none and the three things that look like one are not — see below.

### The two families, and why the difference is the whole design

**Self-describing** hashes carry the algorithm, its cost and the salt inside the
string. `$2y$12$…` says "bcrypt, cost 12, this salt". `detect()` handles them.

**Bare** hashes are just a digest. `5ebe2294ecd0e0f08eab7690d2a6ee69` is 32 hex
characters and nothing more — it could be MD5 of the password, MD5 of
salt+password, MD5 of password+salt, the first half of a SHA-256, or a session
id somebody put in the wrong column. The algorithm, the salt and the salt's
**position** live elsewhere, so a bare hash is **declared**, never detected.

---

## There is no "try them all" mode, and there will not be

The convenient thing to build is a verifier that tries each algorithm until one
matches. It is the one thing that must not exist here.

Verifying a 32-character hex digest against `md5(pw)`, then `md5(salt.pw)`, then
`md5(pw.salt)`, then `substr(sha256(pw), 0, 32)` gives an attacker **four
chances at a collision instead of one** — and a collision in the *weakest*
scheme on the list authenticates a user whose password was stored under the
strongest. The security of the set becomes the security of its worst member.

It is also exactly the kind of mistake that looks like a feature in a migration
tool, because it makes an import "just work" against a database nobody
documented — right up to the first forged login.

So: unambiguous prefixes are detected. Everything else is declared by whoever
read the old application's source and therefore actually knows.

---

## What Appwrite cannot read, and this can

Appwrite was the reference point for this work, and three gaps are worth naming
because they are the difference between "can migrate this system" and "cannot":

- **Salted digests.** Appwrite's `md5` and `sha` importers hash the password and
  *nothing else* — `md5($value)`, `hash('sha256', $value)`. A salted column,
  which is the overwhelming majority of real legacy tables, has no path through
  them at all. Here the salt, its **position** (before or after) and its
  encoding are first-class.
- **scrypt on a stock PHP.** Appwrite's scrypt and scryptMod importers both
  require the `ext-scrypt` PECL extension and throw
  `'The scrypt extension is required'` without it. Almost nobody has it
  installed.
- **Its scrypt parameter names read backwards.** Appwrite's importer takes
  `costCpu` (default 8) and `costMemory` (default 14) and passes them in that
  order as scrypt's **N** and **r** — so a field labelled "memory cost" arrives
  as the *block size*, and the one labelled "CPU cost" is the parameter that
  actually governs memory. An import that trusts the labels produces N=14, r=8,
  which is a valid scrypt call computing a completely different answer, and
  fails every verification. This plugin names its parameters after RFC 7914 and
  nothing else.

---

## Why scrypt is implemented here

PHP has no scrypt. The three things that look like one are not:

- **`ext-scrypt`** is a PECL extension almost nobody has.
- **`sodium_crypto_pwhash_scryptsalsa208sha256()`** takes `opslimit` and
  `memlimit`, **not** N, r and p, and insists on a 32-byte salt. A Node or
  Firebase hash has a 16-byte salt and its own N and r, so this function cannot
  be made to produce the same bytes. Checked rather than assumed — the signature
  on PHP 8.5 is `(int $length, string $password, string $salt, int $opslimit,
  int $memlimit)`.
- **`hash('scrypt', …)`** does not exist.

So ~200 lines of 32-bit arithmetic, and every one of them verifiable.

### It is correct, and that is a measurement

The three published **RFC 7914 §11** vectors pass. The expected values were not
typed from memory — they were generated by **two independent implementations**
on the machine this was written on, Python's `hashlib.scrypt` (OpenSSL) and
Node's `crypto.scryptSync`, which agree with each other and with the RFC.

That matters more here than anywhere else in the plugin: an off-by-one in the
BlockMix shuffle or a missed `& 0xFFFFFFFF` produces output that looks perfectly
random and is simply wrong, and the only symptom would be every imported user
being told their password is incorrect.

### It is slow, and here is the number

**Measured: 1.58 s** at N=16384, r=8, p=1 — exactly Firebase's defaults — on PHP
8.5.12, Apple Silicon, OPcache loaded with JIT disabled. OpenSSL's C
implementation does the same derivation in **45 ms**, so the gap is about 35×.

That is unacceptable for a password scheme and fine for this, because of the
asymmetry above: **one verification per user, ever.** The total cost across a
whole migration is 1.58 s times the number of users who ever log in again.

What it is *not* suitable for is being left in place as the live scheme, which
is what the unconditional upgrade is there to prevent.

The Salsa20/8 core is written as sixteen local variables with the rounds spelled
out rather than a loop over an array of operand indices. Measured over 60,000
calls, the array-indexed version is **2.8× slower** — and that measurement
charges the unrolled side with reflection overhead it does not pay in
production, so the real gap is wider. At 524,288 calls per Firebase
verification, that is the difference between about one and a half seconds and
about four and a half.

---

## Firebase

A Firebase export gives a `passwordHash` and a `salt` per user, plus one
`hash_config` for the whole project. The construction is:

```
derived = scrypt(password, salt ‖ saltSeparator,
                 N = 2^mem_cost, r = rounds, p = 1, dkLen = 64)
stored  = base64( AES-256-CTR(key = derived[0..31],
                              iv  = sixteen zero bytes,
                              plaintext = signerKey) )
```

Three details in that are each a way to get it wrong:

1. The salt and separator are **concatenated** as the scrypt salt. The separator
   is not a delimiter — `Bw==` decodes to a single `0x07`.
2. Only the **first 32 bytes** of the 64-byte derived key are used, as the AES
   key. The other 32 are discarded. OpenSSL **silently accepts a 64-byte key for
   aes-256-ctr** and truncates it — measured — so an implementation that passed
   all 64 would produce a plausible ciphertext of the right length and be wrong
   only sometimes.
3. The password is the **key** and the signer key is the **plaintext**, which is
   backwards from how a password hash normally reads. The output's length
   therefore follows the signer key, not a digest size: a 64-byte signer key
   gives 88 characters of base64.

A fixed zero IV over a fixed plaintext would be a grave mistake in an encryption
scheme. Here that determinism is the requirement, and the key differs for every
password.

**An empty signer key is refused at construction**, because it is a total
authentication bypass: `openssl_encrypt('', 'aes-256-ctr', …)` returns the empty
string (measured, not false), so every password would hash to `''`, and `''`
compares equal to `''`. Reachable by forgetting one field of the export.

`FirebaseParameters::fromExport()` decodes **strictly**. Lenient
`base64_decode()` ignores characters it does not recognise and returns something
plausible for almost any input, so a field mangled by a line break would decode
to a shorter, wrong byte string and fail for every user with nothing to explain
it.

---

## The digest family

```php
DigestParameters::of(
    algorithm:  'md5',
    salt:       $row['salt'],              // RAW, as the old code concatenated it
    placement:  SaltPlacement::Prefix,     // or ::Suffix — see below
    encoding:   DigestEncoding::HexLower,  // or ::HexUpper, ::Base64
    rounds:     1,
    roundInput: DigestRoundInput::Hex,
);
```

**The salt's position cannot be recovered from the data.** `md5('s4lt'.'secret')`
and `md5('secret'.'s4lt')` are both 32 hex characters and neither resembles the
other, so a wrong guess looks exactly like a wrong password — for every user at
once. Prepending is the crypt(3) tradition and what most hand-rolled PHP of the
2000s copied; appending is Joomla's. **Read the old login code.**

**`rounds` re-feeds hex by default.** `md5(md5($password))` written in PHP feeds
the 32-character *hex string* into the second call; written in almost any other
language it feeds the 16 *raw bytes*. The two share no output. Hex is the default
because this family is largely PHP's legacy; `DigestRoundInput::Raw` covers the
rest.

**The salt is applied in round 1 only.** That is a deliberate boundary:
vBulletin's `md5(md5($password) . $salt)` applies it in round *two*, and that is
a different scheme which is **not supported**. Supporting every position would
mean five booleans whose 32 combinations mostly describe nothing real and whose
wrong setting fails silently.

**The algorithm list is an allowlist.** `hash()` offers sixty algorithms
including `crc32b` and `xxh64`. Those are checksums — a 32-bit one has
collisions anybody can find in milliseconds, so a column holding one is not an
authentication check at all. MD5 *is* on the list, precisely because real tables
hold MD5 and the alternative is those users being unable to log in.

---

## Plaintext

Off by default. A plaintext password column is a real thing real schemas have,
and refusing to read one does not make those passwords safer — it makes
migrating off them harder, which is the opposite of the goal.

Turn it on deliberately, with a date on the decision, and turn it off again:

```dotenv
LEGACY_PASSWORD_ALLOW_PLAINTEXT=true
```

---

## Why there are cost ceilings

A self-describing hash carries its own work factor, and **an import file from
the system you are migrating away from is not trusted input.** One row
containing

```
$2y$31$................................
```

is a valid bcrypt hash with 2^31 rounds — hours of CPU for one verification.
Planting it costs nothing, it passes every format check because it *is* a valid
hash, and from then on every login attempt against that account occupies a PHP
worker until the request times out. A handful of such rows is a denial of
service that needs no traffic to trigger.

So the ceilings turn that into a refusal with a reason, checked **before** the
work is spent. They are generous enough that nothing met in practice comes near
them.

| Variable | Default | Covers |
|---|---|---|
| `LEGACY_PASSWORD_MAX_BCRYPT_COST` | `15` | bcrypt's cost |
| `LEGACY_PASSWORD_MAX_ARGON2_MEMORY` | `1048576` (1 GiB, in KiB) | Argon2's `m` |
| `LEGACY_PASSWORD_MAX_ITERATIONS` | `1000000` | phpass, PBKDF2, crypt(3) `rounds=` |
| `LEGACY_PASSWORD_ALLOW_PLAINTEXT` | `false` | the plaintext scheme |

`$P$J` — phpass at 2^21 iterations — is above the default, so the shipped
ceiling genuinely refuses something rather than being a number nothing reaches.

### `password_get_info()` cannot be trusted for Argon2's cost

It reads the declared `m`, `t` and `p` out of a well-formed hash correctly. What
it cannot do is **fail**: it recognises Argon2 by prefix alone, needs neither a
salt nor a hash to be present, and silently substitutes PHP's own defaults for a
parameter field it cannot read. All measured:

```
password_get_info('$argon2id$')                      → algo argon2id, m=65536 (default)
password_get_info('$argon2id$v=19$m=8192,t=2,p=1')   → algo argon2id, m=8192  (no salt, no hash)
password_get_info('…$m=zzz,t=2,p=1$c2FsdA$aaaa')     → algo argon2id, m=65536 (default, silently)
```

So a ceiling consulting it for `m=zzz` would compare 65536 — a number from the
*server's* configuration, not from the hash — and wave through a row whose real
cost is unknown. `Argon2Hash` parses the PHC string instead.

---

## Malformed is not "wrong password"

Both look identical from outside: the user cannot log in. But one is **one
person mistyping** and the other is **a broken import affecting an entire
population** — and collapsing them is how a broken import stays invisible until
support notices that everybody "forgot" at once.

`LegacyVerdict::suggestsMisconfiguration()` is what you route on. It is true for
everything except `WrongPassword`.

```php
if ($verdict->suggestsMisconfiguration()) {
    $logger->error($verdict->logLine());   // not a warning. A population is locked out.
}
```

**None of it may reach the person logging in.** "This account's password is
stored as an unsalted MD5" tells an attacker which accounts are cheapest to
attack offline, and `PlaintextRefused` tells them the column holds the password
itself. The refusal reasons are written for an operator's log; the login
response stays one generic failure for all of them.

---

## `legacy:inspect`

The command that prevents the expensive failure. An import of 50,000 users with
the salt placement declared the wrong way round produces 50,000 rows that look
perfect and verify nothing.

```console
$ hkm cli legacy:inspect '$P$Be.39vipNM3QIErUZ.CevixuseSbRo0'

Hash
┌──────────────────────────┬────────────────────────────────────────────────┐
│ Property                 │ Value                                          │
├──────────────────────────┼────────────────────────────────────────────────┤
│ Length                   │ 34                                             │
│ Detected                 │ phpass                                         │
│ Well formed              │ yes                                            │
│ This build can verify it │ yes                                            │
│ Work factor              │ 8192 iterations of MD5                         │
└──────────────────────────┴────────────────────────────────────────────────┘

$ printf '%s' "$KNOWN_PASSWORD" | hkm cli legacy:inspect '$P$Be.39…' --verify
```

**The password is read from STDIN, never from `argv`.** There is no
`--password` option and there deliberately never will be: an argument is visible
to every other process through `ps` and is written into the shell's history file.
`AbstractCommand::ask()` is not used either, because it **echoes**.

Pointed at a bare digest, the command reports which allowed algorithms produce a
digest of that length in each encoding — and then says plainly that the list is
not a diagnosis, because the length narrows the algorithm and says nothing about
the salt.

---

## Deliberately absent

**Drupal 7 (`$S$…`)** and **MySQL's `PASSWORD()` (`*HEX40`)**. Both real, both
commonly met in an import, both absent for one reason: *nothing on the machine
this was written on could say whether an implementation of them was correct.*

Every scheme that is here is pinned by a known-answer test whose expected value
came from a **different implementation**. For those two there was no second
implementation to check against, and the only remaining option would have been
to write the algorithm from memory and let the test assert whatever the code
happened to produce — a test that cannot fail, guarding a path that gates
logging in.

Adding either needs one thing: **a single real hash of a known password.** The
constructions, so the work starts from something:

- Drupal 7 is phpass with SHA-512 instead of MD5, `$S$` + one count character +
  an 8-character salt, the iterated digest encoded with phpass's `itoa64`, and
  the whole string **truncated to 55 characters**.
- MySQL's is `CONCAT('*', UPPER(SHA1(UNHEX(SHA1(password)))))` — SHA-1 of the
  *raw bytes* of SHA-1. With the `*` stripped by the caller, that is expressible
  today as `DigestParameters::of('sha1', rounds: 2, roundInput:
  DigestRoundInput::Raw, encoding: DigestEncoding::HexUpper)` — but the claim
  that this equals `PASSWORD()` is the part that was never checked, so it is a
  recipe here and not a named algorithm.

**libsodium's `$7$`** is also absent. It needs no implementation —
`sodium_crypto_pwhash_scryptsalsa208sha256_str_verify()` is one call — but a
system new enough to use libsodium's password API is not one this plugin exists
to migrate off.

**No HTTP route.** `POST /legacy/verify` taking a password and a hash is an
*oracle*: it tests arbitrary passwords against arbitrary hashes at the server's
expense. That is a password-cracking service, and at 1.58 seconds per scrypt
call it is also a denial of service with a one-line request.

**No `make()` for any legacy scheme.** This plugin can only ever verify, so
nothing in a project can reach for MD5 by accident. `upgrade()` delegates to the
application's own `HashingPort`, with the application's own cost — a second
opinion here would mean a project that moved to Argon2 silently getting bcrypt
for every migrated user.

---

## Why this is not part of `crypto.services`

That plugin owns `HashingPort`, needs no database, and an importer depends on it
anyway. It was still the wrong home.

**Every project loads `crypto.services`** — it is how passwords are hashed. So
putting MD5, unsalted SHA and plaintext verification there would mean every
application everywhere carries code that can check a password against an
unsalted MD5, and would force a security review of the plugin that defines "how
we hash passwords" to reason about nine deliberately weak schemes that project
will never use.

Here they live in a module a project loads only if it is migrating off
something. Nothing in `crypto.services` can reach a weak algorithm, because the
weak algorithms are not in it.

---

## Testing

```console
vendor/bin/phpunit                      # 336 tests
vendor/bin/phpunit --testsuite Unit     # the fast ones
```

Two suites, split by **cost** rather than by what they touch — everything here
is a pure function, so there is no database and nothing an "integration" suite
would mean. `Slow` holds the scrypt work, which is 1.58 s per derivation.

**`Slow` is not optional.** It carries the RFC 7914 vectors and the Firebase
known-answer tests, which are the only evidence the scrypt implementation is
correct at all.

### Revert checks

Twenty-five guards were broken one at a time to see whether the suite noticed.
Nineteen were caught immediately. One — removing the work-factor ceiling — made
the suite hang, which is itself the proof: without it, a planted `$2y$31$` hash
is attempted rather than refused.

Of the six that passed, **one was a real defect** (below) and **five are
unreachable by construction and kept anyway**, each documented at the line:

| Guard | Why no test can reach it | Why it stays |
|---|---|---|
| `hash_equals` over `===` | the two agree on every input and differ only in timing | `===` leaks the matching prefix length, and for bare digests an attacker can try millions a second locally |
| crypt(3)'s `*0` guard | CHECK 3 already refuses a stored `*0`; probed — PHP's `crypt()` returned `*0` for nothing that passes it | if `*0` ever met a stored `*0`, every password would authenticate for that row |
| `matches()`'s `=== ''` arm | CHECK 1 refuses an empty stored value and no algorithm returns `''` | `hash_equals('', '')` is true, so the only failure is a total bypass |
| Argon2 cost from the parser | CHECK 3 parses with the same class, so anything reaching the ceiling has parsed; probed across six parameter sets, both sources agree | it stops depending on another check's ordering for its correctness |
| bcrypt cost fail-closed | CHECK 3 refuses any bcrypt hash PHP cannot parse | a ceiling that fails *open* on malformed input is decorative for exactly that input |

**The real defect:** the digest length check lived inside `checkDigest()` and
returned `false`, which the caller turned into `WrongPassword` — the exact
verdict the check's own comment said it existed to prevent. So removing it
changed nothing observable, and the suite could not tell it from dead code. It
now runs as CHECK 3a in `decide()`, produces `MalformedHash`, and covers all
three bare families — digest, scrypt and Firebase — because for each of them the
stored length is fully determined by the declared parameters.

---

## Not verified

- **No real Firebase, Django, WordPress or phpBB export has been imported.** The
  constructions are pinned by known-answer tests against independent
  implementations; no live system's data has been through them.
- **`legacy:inspect` has not been run through the real `hkm` CLI.** It has been
  executed directly — twenty tests drive it through `BufferIO` with a
  `php://memory` stream standing in for STDIN, covering both the inspect and
  the `--verify` paths — but nothing has gone through `CliPipeline`, so the
  Provider's `defer()` registration is wired and reasoned about rather than
  observed. Running it is also what found the argon2d reporting defect below,
  which reading it had not.
- **Only this build has run it**: PHP 8.5.12 with Argon2i/Argon2id compiled in,
  all three crypt(3) variants available, and OpenSSL offering aes-256-ctr. The
  `supported()` reporting for a build missing any of those is reasoned about,
  not exercised.
- **No timing analysis.** `hash_equals` is used for every comparison, and that
  it is constant-time is PHP's claim, not a measurement made here.
- **The 1.58 s and 2.8× figures are from one machine.** A test asserts the
  former stays inside a wide band, so a factor-of-ten regression fails the
  suite; the exact number is not portable.

---

## Licence

MIT.
