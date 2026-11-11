<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * A stored password as the old system left it, plus whatever it takes to check.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE NAMED CONSTRUCTORS ARE THE POINT
 * ════════════════════════════════════════════════════════════════════════════
 *
 * There is one constructor per scheme, and each takes exactly the parameters
 * that scheme needs — so a scrypt credential CANNOT be built without its N, r,
 * p, length and salt, and a bcrypt one cannot be built with them.
 *
 * The alternative shape — one constructor taking an algorithm name and an
 * options array — is what every library in this space does, and it moves the
 * check from compile time to a runtime `if (!isset($options['salt']))` buried
 * in a verifier. A missing salt then surfaces as "wrong password" for every
 * affected user, which is the single most expensive way for this to fail,
 * because it is indistinguishable from the thing it is supposed to detect.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE STORED HASH IS TREATED AS SENSITIVE
 * ────────────────────────────────────────────────────────────────────────────
 *
 * A password hash is not a credential — it cannot be replayed — but it is
 * exactly what an offline attacker wants, and for the weak schemes this plugin
 * exists to read, "offline attack" means seconds. An unsalted MD5 in a stack
 * trace, a log line or a `var_dump` of a request is a password, with a delay.
 *
 * So {@see __debugInfo()} redacts it, {@see describe()} never includes it, and
 * {@see label()} gives something safe to put in a message.
 */
final readonly class LegacyCredential
{
    private function __construct(
        public LegacyAlgorithm $algorithm,
        /** The stored value, verbatim. Never logged — see the class docblock. */
        private string $stored,
        public ScryptParameters|FirebaseParameters|DigestParameters|null $parameters = null,
    ) {}

    /** `$2$` / `$2a$` / `$2b$` / `$2x$` / `$2y$`. */
    public static function bcrypt(string $hash): self
    {
        return new self(LegacyAlgorithm::Bcrypt, $hash);
    }

    /** `$argon2i$` / `$argon2id$` (and `$argon2d$`, which PHP cannot verify). */
    public static function argon2(string $hash): self
    {
        return new self(LegacyAlgorithm::Argon2, $hash);
    }

    /** `$1$` md5-crypt, `$5$` sha256-crypt, `$6$` sha512-crypt, or a DES hash. */
    public static function crypt(string $hash): self
    {
        return new self(LegacyAlgorithm::Crypt, $hash);
    }

    /** `$P$` (WordPress, Drupal 6) or `$H$` (phpBB3). */
    public static function phpass(string $hash): self
    {
        return new self(LegacyAlgorithm::Phpass, $hash);
    }

    /** `pbkdf2_sha256$iterations$salt$base64digest` — Django's format. */
    public static function pbkdf2(string $hash): self
    {
        return new self(LegacyAlgorithm::Pbkdf2, $hash);
    }

    /**
     * RFC 7914 scrypt.
     *
     * @param string $digest The stored digest, exactly as the column holds it.
     *                       Which form that is — lower hex, upper hex or
     *                       base64 — is DECLARED on the parameters, because
     *                       implementations disagree and trying each in turn
     *                       would let a wrong declaration succeed and stay
     *                       wrong. See {@see ScryptParameters::$encoding}.
     */
    public static function scrypt(string $digest, ScryptParameters $parameters): self
    {
        return new self(LegacyAlgorithm::Scrypt, $digest, $parameters);
    }

    /** Firebase Authentication's `passwordHash`, base64 as the export writes it. */
    public static function firebaseScrypt(string $hash, FirebaseParameters $parameters): self
    {
        return new self(LegacyAlgorithm::FirebaseScrypt, $hash, $parameters);
    }

    /** A bare digest column — the family most imports actually meet. */
    public static function digest(string $digest, DigestParameters $parameters): self
    {
        return new self(LegacyAlgorithm::Digest, $digest, $parameters);
    }

    /**
     * The password, stored as the user typed it.
     *
     * This exists because the systems that need importing are the ones that
     * were built badly, and a plaintext password column is a real thing that
     * real schemas have. Refusing to read it does not make those passwords
     * safer — it makes the migration off them harder, which is the opposite of
     * the goal.
     *
     * It is refused by default all the same, and has to be enabled
     * deliberately. See {@see LegacyRefusal::PlaintextRefused}.
     */
    public static function plaintext(#[\SensitiveParameter] string $stored): self
    {
        return new self(LegacyAlgorithm::Plaintext, $stored);
    }

    /**
     * The stored value.
     *
     * Deliberately a METHOD and not a public property, so that every read is a
     * call that shows up in a grep. There is exactly one caller in this plugin.
     */
    public function stored(): string
    {
        return $this->stored;
    }

    public function isEmpty(): bool
    {
        return $this->stored === '';
    }

    /**
     * Something safe to put in a log line or an exception message.
     *
     * The algorithm and the length, which together are enough to debug an
     * import, and nothing that helps attack the hash.
     */
    public function label(): string
    {
        return $this->algorithm->value . '/' . \strlen($this->stored) . 'ch';
    }

    /**
     * Status output. No hash, no salt, no key.
     *
     * @return array<string, mixed>
     */
    public function describe(): array
    {
        return [
            'algorithm'       => $this->algorithm->value,
            'self_describing' => $this->algorithm->selfDescribing(),
            'work_factored'   => $this->algorithm->workFactored(),
            'stored_length'   => \strlen($this->stored),
            'parameters'      => $this->parameters?->describe() ?? [],
        ];
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return [
            'algorithm'  => $this->algorithm->value,
            'stored'     => '[redacted: ' . \strlen($this->stored) . ' characters]',
            'parameters' => $this->parameters,
        ];
    }
}
