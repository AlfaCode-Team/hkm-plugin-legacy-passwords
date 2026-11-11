<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * A bare digest column, and everything needed to reproduce it.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THIS IS THE FAMILY MOST IMPORTS ACTUALLY MEET
 * ════════════════════════════════════════════════════════════════════════════
 *
 * bcrypt and Argon2 are easy because the string says what it is. The hard
 * imports are the twenty-year-old PHP applications, and those stored
 * `md5($salt . $password)` or `sha1($password . $salt)` in a `varchar(32)`
 * beside a `salt` column, with the salt's position decided once by whoever
 * wrote the login page and recorded nowhere.
 *
 * Appwrite's importer cannot read any of them: its `md5` and `sha` algorithms
 * hash the password and NOTHING ELSE — `md5($value)`, `hash('sha256', $value)`
 * — so a salted column, which is the overwhelming majority, has no path. That
 * is the gap this class exists to close, and it is why the salt and its
 * placement are first-class here instead of being an afterthought.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THREE AXES, AND THE COMBINATIONS NOT COVERED ARE NAMED
 * ────────────────────────────────────────────────────────────────────────────
 *
 * This covers `encode( hash^rounds( placement(salt, password) ) )`:
 *
 *   • the algorithm      — md5, sha1, sha256, … (an allowlist, see ALLOWED)
 *   • the salt placement — before, after, or absent        {@see SaltPlacement}
 *   • the encoding       — lower hex, upper hex, base64  {@see DigestEncoding}
 *   • rounds > 1         — feeding the digest back in, as hex or as raw bytes
 *
 * THE SALT IS APPLIED IN ROUND 1 ONLY. That is a deliberate boundary, not an
 * oversight: vBulletin's `md5(md5($password) . $salt)` applies it in round
 * TWO, and XenForo's older scheme applies it to a hex digest, and each extra
 * position doubles the configuration surface for one more application.
 *
 * Supporting them as flags would mean five booleans whose 32 combinations
 * mostly describe nothing real, and whose wrong setting fails silently. So
 * they are OUT, said plainly here, and an application with one of those
 * schemes should verify it with four lines of its own rather than configure
 * this class into a shape it was not tested in.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY `rounds` RE-FEEDS HEX BY DEFAULT
 * ────────────────────────────────────────────────────────────────────────────
 *
 * `md5(md5($password))` written in PHP feeds the HEX STRING of the first
 * digest into the second, because `md5()` returns hex unless its second
 * argument says otherwise. Written in almost any other language it feeds the
 * RAW BYTES. The two produce entirely different results, and which one a
 * legacy table holds depends on what language wrote it.
 *
 * Hex is the default because this family of hashes is overwhelmingly PHP's
 * legacy, and {@see DigestRoundInput::Raw} covers the rest. Choosing wrong
 * fails every user, which is the loud failure — there is no partial-success
 * mode to hide in.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE ALGORITHM ALLOWLIST
 * ────────────────────────────────────────────────────────────────────────────
 *
 * `hash()` accepts sixty algorithms on a normal build, including `crc32b` and
 * `xxh64`. Those are CHECKSUMS: they are not merely weak as password hashes,
 * they are trivially invertible, and a 32-bit one has collisions anybody can
 * find in milliseconds — accepting one would mean a `crc32b` column where any
 * of four billion passwords authenticates.
 *
 * So the allowlist is the cryptographic hashes legacy applications actually
 * used for passwords, and nothing else. It is not a judgement about which are
 * still safe — MD5 is on it precisely because real tables hold MD5 and the
 * alternative is those users being unable to log in at all.
 */
final readonly class DigestParameters
{
    /**
     * Hash algorithms a legacy password column plausibly holds.
     *
     * Keyed by name, valued by the raw digest length in bytes, so a truncated
     * column can be rejected before the hash is even computed.
     */
    public const ALLOWED = [
        'md5'        => 16,
        'sha1'       => 20,
        'sha224'     => 28,
        'sha256'     => 32,
        'sha384'     => 48,
        'sha512'     => 64,
        'sha512/224' => 28,
        'sha512/256' => 32,
        'sha3-224'   => 28,
        'sha3-256'   => 32,
        'sha3-384'   => 48,
        'sha3-512'   => 64,
        'ripemd160'  => 20,
        'whirlpool'  => 64,
    ];

    /**
     * A round count above this is not a legacy digest scheme.
     *
     * Some applications iterated a few times — `md5(md5($pw))`, or a loop of
     * 10 — in a doomed attempt at a work factor. A column that genuinely needs
     * thousands of rounds is PBKDF2, which is a different algorithm with its
     * own salt handling and belongs in {@see LegacyAlgorithm::Pbkdf2}. The cap
     * is here so a mistyped `100000` fails with that sentence instead of
     * occupying a worker.
     */
    public const MAX_ROUNDS = 100;

    private function __construct(
        public string $algorithm,
        public string $salt,
        public SaltPlacement $placement,
        public DigestEncoding $encoding,
        public int $rounds,
        public DigestRoundInput $roundInput,
    ) {}

    /**
     * @param string $salt RAW salt bytes, exactly as the source system concatenated
     *                     them. A salt stored as hex text in the database and
     *                     concatenated as that TEXT must be passed as the text —
     *                     this is one of the few places where "the bytes" means
     *                     whatever the original code actually joined.
     *
     * @throws \DomainException when the algorithm is not on the allowlist, or a
     *                          salt is declared with placement None, or rounds
     *                          is out of range.
     */
    public static function of(
        string $algorithm,
        string $salt = '',
        SaltPlacement $placement = SaltPlacement::None,
        DigestEncoding $encoding = DigestEncoding::HexLower,
        int $rounds = 1,
        DigestRoundInput $roundInput = DigestRoundInput::Hex,
    ): self {
        $normalised = strtolower(trim($algorithm));

        if (!isset(self::ALLOWED[$normalised])) {
            throw new \DomainException(\sprintf(
                'Hash algorithm "%s" is not an allowed legacy password digest. Allowed: %s. '
                . 'A checksum such as crc32b is refused on purpose — collisions in one are '
                . 'cheap enough to find that any column holding one is not an authentication '
                . 'check at all.',
                $algorithm,
                implode(', ', array_keys(self::ALLOWED)),
            ));
        }

        // A salt with nowhere to go is a configuration that silently ignores
        // it. Every user then fails, and the declaration LOOKS right — the
        // salt is sitting there in the config being used by nothing.
        if ($salt !== '' && $placement === SaltPlacement::None) {
            throw new \DomainException(
                'A salt was supplied with placement "none", so it would never be used. '
                . 'Declare SaltPlacement::Prefix or ::Suffix — which one it is has to come '
                . 'from the source application\'s code, because the digest cannot say.',
            );
        }

        if ($salt === '' && $placement !== SaltPlacement::None) {
            throw new \DomainException(
                'Placement "' . $placement->value . '" was declared with an empty salt. '
                . 'If the scheme is genuinely unsalted, say SaltPlacement::None, so the '
                . 'intent is in the configuration rather than implied by a blank field.',
            );
        }

        if ($rounds < 1 || $rounds > self::MAX_ROUNDS) {
            throw new \DomainException(\sprintf(
                'rounds must be between 1 and %d; got %d. A scheme needing thousands of '
                . 'iterations is PBKDF2 — use LegacyAlgorithm::Pbkdf2, which handles its '
                . 'salt and iteration count properly.',
                self::MAX_ROUNDS,
                $rounds,
            ));
        }

        return new self(
            algorithm:  $normalised,
            salt:       $salt,
            placement:  $placement,
            encoding:   $encoding,
            rounds:     $rounds,
            roundInput: $roundInput,
        );
    }

    /** Raw digest length in bytes for the declared algorithm. */
    public function digestBytes(): int
    {
        return self::ALLOWED[$this->algorithm];
    }

    /** The string length a correctly-stored digest must have. */
    public function expectedLength(): int
    {
        return $this->encoding->lengthFor($this->digestBytes());
    }

    /**
     * Compute the digest for a password, in the source system's encoding.
     *
     * Pure, and deliberately NOT a comparison: the caller compares with
     * `hash_equals`, so there is exactly one place in this plugin where a
     * digest comparison happens and exactly one place to get the timing right.
     */
    public function compute(#[\SensitiveParameter] string $password): string
    {
        $input = $this->placement->apply($password, $this->salt);

        // Round 1 always hashes the salted password. Later rounds re-feed,
        // and WHAT they re-feed is the roundInput axis.
        $raw = hash($this->algorithm, $input, binary: true);

        for ($round = 2; $round <= $this->rounds; $round++) {
            $raw = hash(
                $this->algorithm,
                $this->roundInput === DigestRoundInput::Hex ? bin2hex($raw) : $raw,
                binary: true,
            );
        }

        return $this->encoding->encode($raw);
    }

    /**
     * Status output. The salt's LENGTH, never the salt.
     *
     * @return array<string, int|string>
     */
    public function describe(): array
    {
        return [
            'algorithm'  => $this->algorithm,
            'placement'  => $this->placement->value,
            'encoding'   => $this->encoding->value,
            'rounds'     => $this->rounds,
            'round_input' => $this->roundInput->value,
            'salt_bytes' => \strlen($this->salt),
        ];
    }

    /** Keep the salt out of a var_dump. */
    public function __debugInfo(): array
    {
        return $this->describe();
    }
}
