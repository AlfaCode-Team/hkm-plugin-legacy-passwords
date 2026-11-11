<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * The out-of-band parameters an RFC 7914 scrypt digest needs.
 *
 * A stored scrypt digest is raw bytes. Nothing in it records N, r, p, the
 * output length or the salt, so all five come from the source system's
 * configuration — which is why this is a declared value object and not
 * something parsed out of a string.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE PARAMETER NAMES ARE A TRAP, AND IT IS WORTH NAMING THE TRAP
 * ════════════════════════════════════════════════════════════════════════════
 *
 * RFC 7914 calls N the "CPU/Memory cost parameter", r the "block size
 * parameter" and p the "parallelization parameter". N is the one that drives
 * BOTH time and memory: memory is `128 * r * N` bytes, so doubling N doubles
 * the memory and the time, while r mostly changes how sequentially that memory
 * is touched.
 *
 * Several systems label them differently, and at least one labels them in a
 * way that reads backwards. Appwrite's scrypt importer takes `costCpu`
 * (default 8) and `costMemory` (default 14) and passes them in that order as N
 * and r — so a value labelled "memory cost" arrives as the BLOCK SIZE, and the
 * one labelled "CPU cost" is the parameter that actually governs memory. An
 * import that trusts the labels and swaps them produces N=14, r=8, which is a
 * perfectly valid scrypt call that computes a completely different answer and
 * fails every single verification.
 *
 * This class therefore names the parameters after the RFC and nothing else.
 * Mapping a source system's labels onto them is the importer's job, and it is
 * a job that has to be done by reading the source system's code rather than
 * its field names.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THERE ARE CEILINGS
 * ────────────────────────────────────────────────────────────────────────────
 *
 * scrypt is memory-hard BY DESIGN: `128 * r * N` bytes get allocated and
 * touched. At N=2^20, r=8 that is a gigabyte, and this implementation is pure
 * PHP, so it is also minutes of CPU. Those numbers come from an import's
 * configuration, which is operator-supplied rather than attacker-supplied — but
 * a typo of one digit in `memoryCost` is a 1000-fold difference, and the
 * failure mode is a worker that stops responding rather than an error anybody
 * can read.
 *
 * So the ceilings exist to turn a typo into a message. They are generous
 * enough to cover every scheme met in practice: Firebase's defaults (N=2^14,
 * r=8) need 16 MB, and the RFC's heaviest published test vector (N=2^20, r=8)
 * is the only thing above the default ceiling.
 */
final readonly class ScryptParameters
{
    /** `128 * r * N` must not exceed this. 2^14 × 8 × 128 = 16 MB for Firebase. */
    public const MAX_MEMORY_BYTES = 256 * 1024 * 1024;

    /** p above this is a misconfiguration; p multiplies the whole ROMix cost. */
    public const MAX_PARALLELISM = 16;

    /** r above this is not a scheme anybody runs; it is a mistyped N. */
    public const MAX_BLOCK_SIZE = 64;

    public const MIN_LENGTH = 16;

    public const MAX_LENGTH = 1024;

    private function __construct(
        /** RFC 7914's N — the CPU/memory cost. A power of two, greater than 1. */
        public int $n,
        /** RFC 7914's r — the block size. */
        public int $r,
        /** RFC 7914's p — the parallelisation factor. */
        public int $p,
        /** Output length in bytes. Must match the stored digest exactly. */
        public int $length,
        /** The salt, as RAW BYTES. See {@see of()} on why that matters. */
        public string $salt,
        /**
         * How the stored digest was written.
         *
         * scrypt implementations disagree: `php-scrypt`'s `scrypt()` returns
         * LOWER-CASE HEX, Node's `crypto.scryptSync` returns a Buffer that
         * most applications then base64 or hex themselves, and Firebase
         * base64s it. So this is declared like every other property of a bare
         * scheme, rather than guessed by trying each form in turn — which
         * would make a wrong declaration succeed anyway and leave the
         * misconfiguration in place for the next person to find.
         */
        public DigestEncoding $encoding,
    ) {}

    /**
     * @param string $salt RAW salt bytes — not base64, not hex.
     *
     * The encoding of the salt is the single most common way a scrypt import
     * goes wrong, because an export writes it base64 and the verification
     * needs the bytes. Passing the base64 TEXT is not an error anything can
     * detect: it is a valid salt, just not the right one, so every user fails
     * and nothing explains why. This class cannot tell the difference either,
     * which is why the parameter is documented rather than validated — the
     * decode belongs at the edge where the export is read.
     *
     * @throws \DomainException when a parameter is outside what scrypt or the
     *                          ceilings allow.
     */
    public static function of(
        int $n,
        int $r,
        int $p,
        int $length,
        string $salt,
        DigestEncoding $encoding = DigestEncoding::HexLower,
    ): self {
        if ($n <= 1 || ($n & ($n - 1)) !== 0) {
            throw new \DomainException(
                'scrypt N must be a power of two greater than 1; got ' . $n
                . '. A value like 14 is a MEMORY COST EXPONENT, not N — N would be 2^14 = 16384.',
            );
        }

        if ($r < 1 || $r > self::MAX_BLOCK_SIZE) {
            throw new \DomainException(
                'scrypt r must be between 1 and ' . self::MAX_BLOCK_SIZE . '; got ' . $r . '.',
            );
        }

        if ($p < 1 || $p > self::MAX_PARALLELISM) {
            throw new \DomainException(
                'scrypt p must be between 1 and ' . self::MAX_PARALLELISM . '; got ' . $p . '.',
            );
        }

        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new \DomainException(
                'scrypt output length must be between ' . self::MIN_LENGTH . ' and '
                . self::MAX_LENGTH . ' bytes; got ' . $length . '.',
            );
        }

        // Float arithmetic, so the comparison needs no reasoning about
        // overflow at all.
        //
        // An earlier version of this comment claimed the integer form could
        // wrap NEGATIVE and sail past the `>` — which is C's behaviour, not
        // PHP's. PHP PROMOTES TO FLOAT on integer overflow rather than
        // wrapping: measured, `128 * 8 * (1 << 60)` is `1.18e21`, not a
        // negative number. So `128 * $r * $n` would have been correct too, and
        // this line is clarity rather than a guard.
        //
        // The float loses precision above 2^53, which does not matter here:
        // any N large enough to reach that is astronomically above the
        // ceiling, so the comparison's answer is unaffected.
        $memory = 128.0 * $r * $n;

        if ($memory > self::MAX_MEMORY_BYTES) {
            throw new \DomainException(\sprintf(
                'scrypt with N=%d and r=%d would allocate %.0f MB, above the %d MB ceiling. '
                . 'If that is genuinely the source system\'s configuration, raise the ceiling '
                . 'deliberately; far more often it is a mistyped N.',
                $n,
                $r,
                $memory / 1048576,
                (int) (self::MAX_MEMORY_BYTES / 1048576),
            ));
        }

        return new self(n: $n, r: $r, p: $p, length: $length, salt: $salt, encoding: $encoding);
    }

    /**
     * Firebase Authentication's parameters, as an export actually states them.
     *
     * A Firebase user export's `hash_config` gives `mem_cost` and `rounds`,
     * NOT N and r — N is `2^mem_cost`. The defaults are `mem_cost: 14` and
     * `rounds: 8`, which is N=16384, r=8, p=1, 64 bytes out.
     */
    public static function firebase(int $memoryCost = 14, int $rounds = 8, string $salt = ''): self
    {
        if ($memoryCost < 1 || $memoryCost > 30) {
            throw new \DomainException(
                'Firebase mem_cost must be between 1 and 30 (it is an EXPONENT: N = 2^mem_cost); got '
                . $memoryCost . '.',
            );
        }

        return self::of(
            n:      1 << $memoryCost,
            r:      $rounds,
            p:      1,
            length: 64,
            salt:   $salt,
            // Firebase's export writes passwordHash base64. This encoding is
            // not used on the Firebase path itself — there the derived key is
            // an AES key rather than the stored value — but it is the right
            // answer for anyone deriving a plain scrypt digest from a Firebase
            // configuration, so it is stated rather than left at the default.
            encoding: DigestEncoding::Base64,
        );
    }

    /** Bytes scrypt will allocate for these parameters. */
    public function memoryBytes(): int
    {
        return 128 * $this->r * $this->n;
    }

    /**
     * Describe the parameters WITHOUT the salt.
     *
     * The salt is not a secret in the sense a password is, but it is the thing
     * that makes a stolen digest expensive to attack, so it does not belong in
     * a status line that may be printed, logged or returned by a health check.
     *
     * @return array<string, int|string>
     */
    public function describe(): array
    {
        return [
            'n'         => $this->n,
            'r'         => $this->r,
            'p'         => $this->p,
            'length'    => $this->length,
            'memory_mb' => (int) round($this->memoryBytes() / 1048576),
            'encoding'  => $this->encoding->value,
            'salt_bytes' => \strlen($this->salt),
        ];
    }
}
