<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * The answer to "does this password match this legacy hash".
 *
 * ════════════════════════════════════════════════════════════════════════════
 * A SUCCESSFUL VERDICT IS ALWAYS AN INSTRUCTION TO RE-HASH
 * ════════════════════════════════════════════════════════════════════════════
 *
 * There is no `needsRehash()` here, and the absence is deliberate. For a
 * modern hasher that question is real — bcrypt at cost 10 is fine, just not as
 * fine as cost 12. For a LEGACY hash it is not a question: the whole reason
 * this plugin exists is that the hash should not be there any more, and the
 * one moment the plaintext is available to replace it is right now, inside the
 * request that just verified it.
 *
 * So {@see granted()} carries no condition, and the method that tells a caller
 * what to do about it is named {@see mustUpgrade()} and returns true whenever
 * the verification succeeded. If a caller ignores it, the user re-verifies
 * against the legacy hash on every future login — paying, for scrypt, about a
 * second and a half of CPU each time, forever.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT THIS DOES NOT CARRY
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Not the password, not the hash, and not the new hash. Producing the
 * replacement is a separate call, because the verdict is a value that may be
 * logged and the replacement is a secret-adjacent string that must not be.
 */
final readonly class LegacyVerdict
{
    private function __construct(
        public bool $verified,
        public LegacyAlgorithm $algorithm,
        public ?LegacyRefusal $refusal,
    ) {}

    public static function granted(LegacyAlgorithm $algorithm): self
    {
        return new self(verified: true, algorithm: $algorithm, refusal: null);
    }

    public static function refused(LegacyAlgorithm $algorithm, LegacyRefusal $refusal): self
    {
        return new self(verified: false, algorithm: $algorithm, refusal: $refusal);
    }

    /**
     * Whether the caller must now replace the stored hash.
     *
     * True for every successful verification. See the class docblock.
     */
    public function mustUpgrade(): bool
    {
        return $this->verified;
    }

    /**
     * Whether this failure is the deployment's problem rather than the user's.
     *
     * A caller should route these somewhere an operator sees, because each one
     * means a whole population cannot log in — not one person who mistyped.
     */
    public function suggestsMisconfiguration(): bool
    {
        return $this->refusal?->suggestsMisconfiguration() ?? false;
    }

    /**
     * A log line. Safe to write anywhere — no hash, no salt, no password.
     *
     * The algorithm IS included, and that is a deliberate trade: knowing that
     * some accounts are on unsalted MD5 is operationally essential (it is the
     * number you watch go to zero during a migration) and it is not a secret
     * from anyone who already has the database. What must not happen is this
     * string reaching the person logging in, which is why the service logs it
     * and the HTTP layer returns nothing but a generic failure.
     */
    public function logLine(): string
    {
        if ($this->verified) {
            return \sprintf(
                'legacy password verified algorithm=%s work_factored=%s action=upgrade',
                $this->algorithm->value,
                $this->algorithm->workFactored() ? 'yes' : 'no',
            );
        }

        return \sprintf(
            'legacy password refused algorithm=%s reason=%s operational=%s',
            $this->algorithm->value,
            $this->refusal?->value ?? 'unknown',
            $this->suggestsMisconfiguration() ? 'yes' : 'no',
        );
    }
}
