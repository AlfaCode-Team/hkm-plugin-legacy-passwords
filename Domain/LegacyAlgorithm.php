<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * The password schemes this plugin can verify.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * TWO FAMILIES, AND THE DIFFERENCE IS THE WHOLE DESIGN
 * ════════════════════════════════════════════════════════════════════════════
 *
 * SELF-DESCRIBING schemes carry everything needed to verify inside the stored
 * string: the algorithm, its cost parameters and the salt. `$2y$12$…` says
 * "bcrypt, cost 12, this salt". Hand one of those to {@see HashDetector} and it
 * knows what to do.
 *
 * BARE schemes store only a digest. `5ebe2294ecd0e0f08eab7690d2a6ee69` is a
 * 32-character hex string and nothing more: it could be MD5 of the password,
 * MD5 of salt+password, MD5 of password+salt, the first half of a SHA-256, or
 * a session id somebody put in the wrong column. The algorithm, the salt and
 * the salt's POSITION live somewhere else — another column, or a constant
 * compiled into the application that produced it.
 *
 * So a bare scheme can NEVER be detected, only DECLARED, and this enum's
 * {@see selfDescribing()} is what keeps those two paths apart.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THERE IS NO "TRY THEM ALL" MODE
 * ────────────────────────────────────────────────────────────────────────────
 *
 * The convenient thing to build is a verifier that tries every algorithm until
 * one matches. It is also the one thing that must not exist here.
 *
 * Verifying a 32-char hex digest against `md5(pw)`, then `md5(salt.pw)`, then
 * `md5(pw.salt)`, then `substr(sha256(pw), 0, 32)` gives an attacker four
 * chances instead of one, and a collision in the WEAKEST scheme on the list
 * authenticates a user whose password was stored under the strongest. The
 * security of the set becomes the security of its worst member.
 *
 * It is also the kind of mistake that looks like a feature in a migration
 * tool, because it makes an import "just work" on a database nobody documented
 * — right up to the first forged login.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IS DELIBERATELY ABSENT
 * ────────────────────────────────────────────────────────────────────────────
 *
 * DRUPAL 7 (`$S$…`) and MySQL's `PASSWORD()` (`*HEX40`) are both real, both
 * commonly met in an import, and both ABSENT — for one reason, which is that
 * nothing on the machine this was written on can say whether an implementation
 * of them is correct.
 *
 * Every scheme below is pinned by a known-answer test whose expected value was
 * produced by something other than this code: Python's and Node's scrypt for
 * RFC 7914, Node's scrypt plus Node's AES-256-CTR for Firebase, Python's
 * `hashlib` for PBKDF2 and the digests, `openssl passwd` for the crypt(3)
 * family, a separate PHP implementation for phpass, and PHP's own
 * `password_hash` for bcrypt and Argon2.
 *
 * For Drupal's `$S$` and MySQL's `*HEX40` there was no second implementation
 * to check against, and the only remaining option would have been to write the
 * algorithm from memory and let the test assert whatever the code happened to
 * produce — a test that cannot fail, guarding a path that gates logging in.
 *
 * An implementer who has an oracle can add them, and the constructions are
 * recorded in the README so the work starts from something rather than
 * nothing. What is needed is small: ONE real hash of a known password.
 */
enum LegacyAlgorithm: string
{
    /** `$2$` / `$2a$` / `$2b$` / `$2x$` / `$2y$` — PHP, Laravel, Ruby, Node. */
    case Bcrypt = 'bcrypt';

    /** `$argon2i$` / `$argon2id$` — PHP 7.2+, libsodium, Argon2 reference. */
    case Argon2 = 'argon2';

    /** `$1$` md5-crypt, `$5$` sha256-crypt, `$6$` sha512-crypt — /etc/shadow, Dovecot. */
    case Crypt = 'crypt';

    /** `$P$` WordPress / Drupal 6, `$H$` phpBB3 — the "portable" phpass hash. */
    case Phpass = 'phpass';

    /** `pbkdf2_sha256$iterations$salt$digest` — Django, and anything copying it. */
    case Pbkdf2 = 'pbkdf2';

    /** Bare: RFC 7914 scrypt. Node's `crypto.scrypt`, Go, Rust, php-scrypt. */
    case Scrypt = 'scrypt';

    /** Bare: Firebase Authentication's modified scrypt. */
    case FirebaseScrypt = 'firebase-scrypt';

    /** Bare: one pass of a plain digest, optionally salted. Everything else. */
    case Digest = 'digest';

    /** Bare: the password itself. Refused unless explicitly enabled. */
    case Plaintext = 'plaintext';

    /**
     * Whether a stored hash of this scheme identifies itself.
     *
     * Only a self-describing scheme may be produced by {@see HashDetector}.
     * A bare one has to be declared by whoever knows what the source system
     * did, because the string alone cannot say.
     */
    public function selfDescribing(): bool
    {
        return match ($this) {
            self::Bcrypt, self::Argon2, self::Crypt, self::Phpass, self::Pbkdf2 => true,
            self::Scrypt, self::FirebaseScrypt, self::Digest, self::Plaintext   => false,
        };
    }

    /**
     * Whether this scheme applies a deliberate work factor.
     *
     * Not cosmetic — it is the difference between a stolen table that costs
     * years to attack and one that costs an afternoon. {@see Digest} and
     * {@see Plaintext} answer false, which is why an upgrade is urgent rather
     * than merely tidy, and why the service logs the distinction.
     */
    public function workFactored(): bool
    {
        return match ($this) {
            self::Bcrypt, self::Argon2, self::Crypt, self::Phpass,
            self::Pbkdf2, self::Scrypt, self::FirebaseScrypt => true,
            self::Digest, self::Plaintext                    => false,
        };
    }

    /**
     * A sentence an operator reads in a migration report.
     *
     * Deliberately plain about the weak ones. "digest" sounds respectable;
     * "a single unsalted pass of a fast hash" is what it is.
     */
    public function explain(): string
    {
        return match ($this) {
            self::Bcrypt         => 'bcrypt — Blowfish-based, salt and cost in the hash',
            self::Argon2         => 'Argon2 — memory-hard, parameters in the hash',
            self::Crypt          => 'crypt(3) — MD5, SHA-256 or SHA-512 rounds, salt in the hash',
            self::Phpass         => 'phpass — 2^n iterated MD5, as used by WordPress and phpBB3',
            self::Pbkdf2         => 'PBKDF2-HMAC — iteration count and salt in the hash',
            self::Scrypt         => 'scrypt — memory-hard, parameters supplied out of band',
            self::FirebaseScrypt => 'Firebase scrypt — scrypt, then AES-256-CTR over a signer key',
            self::Digest         => 'a single pass of a fast hash, salted or not — no work factor at all',
            self::Plaintext      => 'the password itself, stored as written — no hash at all',
        };
    }
}
