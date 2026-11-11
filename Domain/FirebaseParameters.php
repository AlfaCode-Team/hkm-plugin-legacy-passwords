<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * The four things a Firebase Authentication password hash needs.
 *
 * Firebase does not store a self-describing hash. A user export gives a
 * `passwordHash` and a `salt` per user, and ONE `hash_config` for the whole
 * project:
 *
 *     "hash_config": {
 *         "algorithm": "SCRYPT",
 *         "base64_signer_key": "jxspr8Ki0RYycVU8…",
 *         "base64_salt_separator": "Bw==",
 *         "rounds": 8,
 *         "mem_cost": 14
 *     }
 *
 * So verification needs the per-user salt AND three project-wide values, and
 * getting any of them wrong fails every user identically. The signer key in
 * particular is a project SECRET: it is the thing that makes the exported
 * hashes useless to anyone who only has the export.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE CONSTRUCTION, WHICH IS NOT scrypt-AND-THEN-COMPARE
 * ════════════════════════════════════════════════════════════════════════════
 *
 *     derived = scrypt(password, salt ‖ saltSeparator, N = 2^mem_cost,
 *                      r = rounds, p = 1, dkLen = 64)
 *     stored  = base64( AES-256-CTR( key = derived[0..31],
 *                                    iv  = 16 zero bytes,
 *                                    plaintext = signerKey ) )
 *
 * Three details in that are each a way to get it wrong:
 *
 *  1. The salt and the separator are CONCATENATED as the scrypt salt. The
 *     separator is not a delimiter in a string sense — it is bytes appended to
 *     the salt, and `Bw==` decodes to a single 0x07.
 *  2. Only the FIRST 32 bytes of the 64-byte derived key are used, as the AES
 *     key. The other 32 are discarded.
 *  3. The password is the KEY and the signer key is the PLAINTEXT, which is
 *     backwards from how a password hash normally reads. The output's length
 *     is therefore the signer key's length, not a digest length — a 64-byte
 *     signer key yields an 88-character base64 hash.
 *
 * A zero IV with a fixed plaintext would be a serious mistake in an encryption
 * scheme, because the same key always produces the same ciphertext. Here that
 * is the point: it is being used as a deterministic function, and the key is
 * different for every password.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * EVERY VALUE HERE IS RAW BYTES
 * ────────────────────────────────────────────────────────────────────────────
 *
 * The export writes all three base64-encoded, and the verification needs the
 * decoded bytes. Passing the base64 TEXT through is undetectable — it is a
 * valid salt and a valid key, just not the right ones — so the decode happens
 * at the edge that reads the export, and {@see fromExport()} exists to make
 * that the obvious path rather than something each importer re-does.
 */
final readonly class FirebaseParameters
{
    /** Firebase's defaults, and what almost every project uses. */
    public const DEFAULT_MEMORY_COST = 14;

    public const DEFAULT_ROUNDS = 8;

    /** The derived key is 64 bytes and AES-256 uses the first 32. */
    public const DERIVED_LENGTH = 64;

    public const AES_KEY_LENGTH = 32;

    private function __construct(
        /** Per-user salt, RAW bytes. */
        public string $salt,
        /** Project-wide salt separator, RAW bytes. Usually a single 0x07. */
        public string $saltSeparator,
        /** Project-wide signer key, RAW bytes. A SECRET. */
        public string $signerKey,
        /** `mem_cost` from hash_config — an exponent, N = 2^this. */
        public int $memoryCost,
        /** `rounds` from hash_config — scrypt's r. */
        public int $rounds,
    ) {}

    /**
     * @param string $salt          RAW per-user salt bytes.
     * @param string $saltSeparator RAW separator bytes.
     * @param string $signerKey     RAW signer key bytes.
     *
     * @throws \DomainException when a value is empty or the cost is impossible.
     */
    public static function of(
        string $salt,
        string $saltSeparator,
        #[\SensitiveParameter] string $signerKey,
        int $memoryCost = self::DEFAULT_MEMORY_COST,
        int $rounds = self::DEFAULT_ROUNDS,
    ): self {
        // An empty signer key is the one that must not pass. It would still
        // produce a hash — AES-256-CTR of nothing is nothing, so every user
        // would hash to the empty string and therefore to each other. A
        // verification that compares '' against '' succeeds for EVERY
        // password, which is a total authentication bypass reached by
        // forgetting one field of the export.
        if ($signerKey === '') {
            throw new \DomainException(
                'The Firebase signer key is empty. Refusing to continue: with no signer key '
                . 'there is no plaintext to encrypt, every password would hash to the same '
                . 'empty string, and every password would therefore verify. Read '
                . 'base64_signer_key out of the export\'s hash_config.',
            );
        }

        if ($saltSeparator === '') {
            throw new \DomainException(
                'The Firebase salt separator is empty. It is base64_salt_separator in the '
                . 'export\'s hash_config, and it is part of the scrypt salt — omitting it '
                . 'changes the derived key for every user.',
            );
        }

        if ($salt === '') {
            throw new \DomainException(
                'The per-user Firebase salt is empty. It is the `salt` field on the user '
                . 'record, not on hash_config.',
            );
        }

        // Validates mem_cost/rounds, and rejects a mem_cost that was passed
        // as N (16384 instead of 14) before it allocates 2^16384 bytes.
        ScryptParameters::firebase(memoryCost: $memoryCost, rounds: $rounds, salt: 'x');

        return new self(
            salt:          $salt,
            saltSeparator: $saltSeparator,
            signerKey:     $signerKey,
            memoryCost:    $memoryCost,
            rounds:        $rounds,
        );
    }

    /**
     * Build from the base64 strings a Firebase export actually contains.
     *
     * This is the path an importer should use. It decodes strictly, so a field
     * that is not valid base64 fails here with a message naming the field,
     * rather than silently decoding to a shorter and wrong byte string —
     * `base64_decode()` in its default lenient mode ignores invalid characters
     * and returns something plausible for almost any input.
     *
     * @throws \DomainException when a field is absent or not valid base64.
     */
    public static function fromExport(
        string $base64Salt,
        string $base64SaltSeparator,
        #[\SensitiveParameter] string $base64SignerKey,
        int $memoryCost = self::DEFAULT_MEMORY_COST,
        int $rounds = self::DEFAULT_ROUNDS,
    ): self {
        return self::of(
            salt:          self::decode($base64Salt, 'salt'),
            saltSeparator: self::decode($base64SaltSeparator, 'base64_salt_separator'),
            signerKey:     self::decode($base64SignerKey, 'base64_signer_key'),
            memoryCost:    $memoryCost,
            rounds:        $rounds,
        );
    }

    /** The scrypt parameters this configuration implies. */
    public function scrypt(): ScryptParameters
    {
        return ScryptParameters::firebase(
            memoryCost: $this->memoryCost,
            rounds:     $this->rounds,
            // The separator is appended to the salt, not used as a delimiter.
            salt:       $this->salt . $this->saltSeparator,
        );
    }

    /**
     * Status output. NEVER the signer key, and never the salt.
     *
     * @return array<string, int|string>
     */
    public function describe(): array
    {
        return [
            'mem_cost'        => $this->memoryCost,
            'rounds'          => $this->rounds,
            'n'               => 1 << $this->memoryCost,
            'salt_bytes'      => \strlen($this->salt),
            'separator_bytes' => \strlen($this->saltSeparator),
            // Length only. The key itself is what makes the export useless to
            // a thief who has only the export.
            'signer_key'      => '[redacted: ' . \strlen($this->signerKey) . ' bytes]',
        ];
    }

    /** Redact the signer key from a var_dump or an uncaught-exception dump. */
    public function __debugInfo(): array
    {
        return [
            'salt'          => '[redacted: ' . \strlen($this->salt) . ' bytes]',
            'saltSeparator' => '[redacted: ' . \strlen($this->saltSeparator) . ' bytes]',
            'signerKey'     => '[redacted: ' . \strlen($this->signerKey) . ' bytes]',
            'memoryCost'    => $this->memoryCost,
            'rounds'        => $this->rounds,
        ];
    }

    private static function decode(string $value, string $field): string
    {
        if ($value === '') {
            throw new \DomainException(
                'The Firebase export field `' . $field . '` is empty.',
            );
        }

        // Strict: invalid characters make this return false rather than being
        // skipped. The lenient default would turn a truncated or
        // whitespace-mangled field into a shorter byte string that verifies
        // nothing and explains nothing.
        $decoded = base64_decode($value, true);

        if ($decoded === false || $decoded === '') {
            throw new \DomainException(
                'The Firebase export field `' . $field . '` is not valid base64. '
                . 'Copy it verbatim out of hash_config — a line break or a stray quote is enough '
                . 'to break the decode.',
            );
        }

        return $decoded;
    }
}
