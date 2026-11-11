<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

/**
 * Why a legacy verification did not succeed.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE DISTINCTION THIS ENUM EXISTS TO MAKE
 * ════════════════════════════════════════════════════════════════════════════
 *
 * `WrongPassword` is an ordinary authentication failure: the user typed the
 * wrong thing, it happens thousands of times a day, and nobody needs to know.
 *
 * Everything else is an OPERATIONAL failure — the import is misconfigured, the
 * stored hash is truncated, the scheme is one this build cannot verify. Those
 * are not "wrong password", and collapsing them into it is how a broken import
 * becomes invisible: every affected user simply cannot log in, support is told
 * "they must have forgotten it", and the real cause surfaces weeks later.
 *
 * So the two are separated here, and {@see suggestsMisconfiguration()} marks
 * which half belongs in an alert rather than an access log.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT THE CALLER MUST STILL NOT DO
 * ────────────────────────────────────────────────────────────────────────────
 *
 * None of this may reach the person logging in. "This account's password is
 * stored as an unsalted MD5" is a sentence that tells an attacker which
 * accounts are cheapest to attack offline, and `PlaintextRefused` tells them
 * the column holds the password itself.
 *
 * The login response is the same for every value here. The reason goes to the
 * log, which is why {@see explain()} is written for an operator and not for a
 * form.
 */
enum LegacyRefusal: string
{
    /** The password did not match. The ordinary case. */
    case WrongPassword = 'wrong_password';

    /** The stored string is not a valid hash of the declared scheme. */
    case MalformedHash = 'malformed_hash';

    /** The scheme needs out-of-band parameters that were not supplied. */
    case MissingParameters = 'missing_parameters';

    /** The scheme is known but this build cannot run it. */
    case Unsupported = 'unsupported';

    /** The declared work factor exceeds the configured ceiling. */
    case CostRefused = 'cost_refused';

    /** The scheme is `plaintext` and plaintext has not been enabled. */
    case PlaintextRefused = 'plaintext_refused';

    public function explain(): string
    {
        return match ($this) {
            self::WrongPassword     => 'the password did not match the stored hash',
            self::MalformedHash     => 'the stored value is not a well-formed hash of the declared scheme '
                . '— check the column was imported whole and not truncated',
            self::MissingParameters => 'this scheme stores only a digest, so its algorithm, salt and cost '
                . 'have to be supplied; none were',
            self::Unsupported       => 'this build cannot verify that scheme — see describe() for the list '
                . 'it can',
            self::CostRefused       => 'the hash declares a work factor above the configured ceiling, so it '
                . 'was refused rather than allowed to occupy a worker for minutes',
            self::PlaintextRefused  => 'the scheme is plaintext and plaintext verification is disabled; '
                . 'enable it deliberately and only for the length of the migration',
        };
    }

    /**
     * Whether this points at the deployment rather than at the user.
     *
     * A `WrongPassword` belongs in an access log. Everything else belongs
     * somewhere an operator will actually see it, because every one of them
     * means a population of users cannot log in at all.
     */
    public function suggestsMisconfiguration(): bool
    {
        return $this !== self::WrongPassword;
    }
}
