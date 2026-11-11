<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain;

use Plugins\LegacyPasswords\Domain\Algorithms\Phpass;

/**
 * Recognise a stored hash that says what it is.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THIS IS NOT A GUESSER, AND THE DISTINCTION IS THE SECURITY BOUNDARY
 * ════════════════════════════════════════════════════════════════════════════
 *
 * Every prefix below is UNAMBIGUOUS: `$2y$` is bcrypt and cannot be anything
 * else. A string this class does not recognise comes back as null, and null
 * means "you have to tell me" — never "let me try a few things".
 *
 * The thing that must not exist is the other kind of detector, the one that
 * looks at `5ebe2294ecd0e0f08eab7690d2a6ee69` and reasons "32 hex characters,
 * that will be MD5". It will not do, for two reasons:
 *
 *  1. It is WRONG often enough to matter. 32 hex characters is MD5, or the
 *     first half of a SHA-256, or NTLM, or a salted MD5 whose salt lives in
 *     the next column, or a GUID with the dashes stripped.
 *  2. Guessing WIDENS THE ATTACK SURFACE. A guesser that falls back through
 *     several algorithms gives an attacker several chances at a collision
 *     instead of one, and the set is only as strong as its weakest member.
 *
 * So the bare family — scrypt, Firebase, plain digests, plaintext — is never
 * detected. It is declared through the named constructors on
 * {@see LegacyCredential}, by whoever read the source application's code and
 * therefore actually knows.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * TWO THINGS THAT COULD BE DETECTED AND ARE NOT
 * ────────────────────────────────────────────────────────────────────────────
 *
 * A DES `crypt()` hash is thirteen characters with a two-character salt and no
 * prefix at all. `crypt()` can verify one, so {@see LegacyCredential::crypt()}
 * accepts it — but nothing here will RECOGNISE it, because a thirteen-
 * character alphanumeric string is also a truncated column, a session id, or a
 * username. Declaring it is fine; inferring it is not.
 *
 * `$7$` is libsodium's scrypt crypt format, which
 * `sodium_crypto_pwhash_scryptsalsa208sha256_str_verify()` verifies in one
 * call with no implementation to get wrong. It is left out because it is not a
 * LEGACY format — a system new enough to use libsodium's password API is not
 * the kind of system this plugin exists to migrate off, and the one-line
 * recipe is in the README for anyone who meets one.
 */
final class HashDetector
{
    /**
     * Unambiguous prefixes, longest first.
     *
     * ORDER IS LOAD-BEARING. `$argon2id$` must be tested before `$argon2i$`,
     * because the shorter string is a prefix of the longer one and matching it
     * first would classify every Argon2id hash as Argon2i. It happens not to
     * matter today — both map to the same enum case and `password_verify()`
     * reads the real variant out of the string itself — but it would matter
     * the moment anything branched on the variant, and relying on that is how
     * a latent bug becomes a live one.
     *
     * @var array<string, LegacyAlgorithm>
     */
    private const PREFIXES = [
        '$argon2id$' => LegacyAlgorithm::Argon2,
        '$argon2i$'  => LegacyAlgorithm::Argon2,
        '$argon2d$'  => LegacyAlgorithm::Argon2,
        '$2a$'       => LegacyAlgorithm::Bcrypt,
        '$2b$'       => LegacyAlgorithm::Bcrypt,
        '$2x$'       => LegacyAlgorithm::Bcrypt,
        '$2y$'       => LegacyAlgorithm::Bcrypt,
        '$2$'        => LegacyAlgorithm::Bcrypt,
        '$P$'        => LegacyAlgorithm::Phpass,
        '$H$'        => LegacyAlgorithm::Phpass,
        '$1$'        => LegacyAlgorithm::Crypt,
        '$5$'        => LegacyAlgorithm::Crypt,
        '$6$'        => LegacyAlgorithm::Crypt,
        'pbkdf2_'    => LegacyAlgorithm::Pbkdf2,
    ];

    /**
     * The algorithm a stored string declares, or null if it declares none.
     *
     * Only the ALGORITHM — not whether the string is a valid hash of it. A
     * truncated `$2y$` is still bcrypt, and reporting it as "unrecognised"
     * would send an operator looking for the wrong problem. The verifier is
     * what distinguishes malformed from wrong.
     */
    public static function algorithm(string $stored): ?LegacyAlgorithm
    {
        foreach (self::PREFIXES as $prefix => $algorithm) {
            if (str_starts_with($stored, $prefix)) {
                return $algorithm;
            }
        }

        return null;
    }

    /**
     * Build a credential from a self-describing hash, or null.
     *
     * Null for anything bare. That is not a failure — it is the contract: a
     * bare hash needs parameters this function has no way to know, so it hands
     * the decision back rather than inventing one.
     */
    public static function detect(string $stored): ?LegacyCredential
    {
        $algorithm = self::algorithm($stored);

        if ($algorithm === null) {
            return null;
        }

        return match ($algorithm) {
            LegacyAlgorithm::Bcrypt => LegacyCredential::bcrypt($stored),
            LegacyAlgorithm::Argon2 => LegacyCredential::argon2($stored),
            LegacyAlgorithm::Crypt  => LegacyCredential::crypt($stored),
            LegacyAlgorithm::Phpass => LegacyCredential::phpass($stored),
            LegacyAlgorithm::Pbkdf2 => LegacyCredential::pbkdf2($stored),
            // Unreachable today: PREFIXES maps to those five and nothing
            // else. Without this arm, adding a sixth prefix without a
            // matching case would raise \UnhandledMatchError, whose message
            // names the enum value but not what the author forgot to do.
            default => throw new \LogicException(
                'HashDetector recognised ' . $algorithm->value
                . ' but has no credential constructor for it. A prefix was added to '
                . 'PREFIXES without a matching arm here.',
            ),
        };
    }

    /**
     * Whether a self-describing hash is well formed for its own scheme.
     *
     * Used to tell MALFORMED from WRONG PASSWORD. The two have the same shape
     * — verification simply fails — but completely different causes: one is a
     * broken import affecting a whole population, the other is one person
     * mistyping. Collapsing them is how a broken import stays invisible for
     * weeks.
     */
    public static function isWellFormed(string $stored, LegacyAlgorithm $algorithm): bool
    {
        return match ($algorithm) {
            // For BCRYPT, password_get_info() is the right tool: it reports
            // the algorithm only for a string it can actually use, and
            // rejects a truncated one. Measured — `$2y$12$abcdefghijklmnopqrstuv`
            // comes back with algo => null.
            LegacyAlgorithm::Bcrypt => password_get_info($stored)['algo'] !== null,

            // For ARGON2 it is not. password_get_info() recognises Argon2 by
            // PREFIX ALONE — the bare string `$argon2id$` is reported as a
            // valid argon2id hash — so it cannot distinguish a real hash from
            // a truncated one, and the `options` it returns are PHP's own
            // defaults rather than the hash's parameters. Both were measured.
            // {@see Algorithms\Argon2Hash} parses the PHC string properly.
            LegacyAlgorithm::Argon2 => Algorithms\Argon2Hash::parse($stored) !== null,

            // crypt(3) output is `$id$...$...` with a non-empty hash section,
            // or a 13-character DES hash. The `*0`/`*1` that crypt() returns
            // on a bad salt is 2-3 characters and fails both.
            LegacyAlgorithm::Crypt => self::isCryptFormed($stored),

            LegacyAlgorithm::Phpass => Phpass::isWellFormed($stored),

            LegacyAlgorithm::Pbkdf2
                => Algorithms\Pbkdf2Hash::parse($stored) !== null,

            // A bare scheme has no form to check. Its "well-formedness" is
            // the declared digest length, which the verifier checks against
            // the declared parameters because only they can say what it is.
            LegacyAlgorithm::Scrypt, LegacyAlgorithm::FirebaseScrypt,
            LegacyAlgorithm::Digest, LegacyAlgorithm::Plaintext => true,
        };
    }

    private static function isCryptFormed(string $stored): bool
    {
        // DES: thirteen characters from the crypt(3) alphabet.
        if (\strlen($stored) === 13 && $stored[0] !== '$') {
            return strspn($stored, './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') === 13;
        }

        // Modular crypt: `$id$` [`rounds=N$`] `salt$hash`.
        //
        // THE `rounds=` FIELD IS NOT OPTIONAL TO HANDLE. sha256-crypt and
        // sha512-crypt both accept an explicit iteration count, and
        // `$6$rounds=5000$salt$hash` is a perfectly ordinary hash that any
        // /etc/shadow or Dovecot export may contain. A pattern that ignored it
        // would read `rounds=5000` as the salt, find `salt$hash` as the hash
        // section, measure the wrong length and reject the row as malformed —
        // for every user whose hash carried a rounds field, which on some
        // systems is all of them.
        //
        // md5-crypt (`$1$`) has no rounds field, so it is spelled separately
        // rather than being allowed a syntax it does not have.
        $pattern = '/^\$1\$[^$]{1,8}\$([^$]+)$|^\$([56])\$(?:rounds=\d+\$)?[^$]+\$([^$]+)$/D';

        if (!preg_match($pattern, $stored, $matches)) {
            return false;
        }

        // The hash section's length is fixed per variant: md5-crypt 22
        // characters, sha256-crypt 43, sha512-crypt 86. Checking only
        // "non-empty" would accept a column truncated mid-hash and report
        // every affected row as a wrong password.
        if (($matches[1] ?? '') !== '') {
            return \strlen($matches[1]) === 22;
        }

        return \strlen($matches[3]) === ($matches[2] === '5' ? 43 : 86);
    }
}
