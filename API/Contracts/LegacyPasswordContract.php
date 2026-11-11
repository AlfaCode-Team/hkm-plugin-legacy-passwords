<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\API\Contracts;

use Plugins\LegacyPasswords\Domain\LegacyAlgorithm;
use Plugins\LegacyPasswords\Domain\LegacyCredential;
use Plugins\LegacyPasswords\Domain\LegacyVerdict;

/**
 * Verify a password against a hash some other system wrote, then replace it.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE ONE FLOW THIS EXISTS FOR
 * ════════════════════════════════════════════════════════════════════════════
 *
 *     $credential = $legacy->detect($row['password'])            // or declare it
 *         ?? LegacyCredential::digest($row['password'], $params);
 *
 *     $verdict = $legacy->verify($password, $credential);
 *
 *     if (!$verdict->verified) {
 *         if ($verdict->suggestsMisconfiguration()) {
 *             $logger->error($verdict->logLine());   // a POPULATION cannot log in
 *         }
 *         return null;                               // generic failure to the user
 *     }
 *
 *     // The one moment the plaintext exists. Take it.
 *     $users->replacePassword($row['id'], $legacy->upgrade($password));
 *
 *     return $identity;
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY UPGRADING IS NOT OPTIONAL, AND NOT DONE HERE
 * ────────────────────────────────────────────────────────────────────────────
 *
 * A legacy hash can only ever be re-hashed during a login, because that is the
 * only moment the plaintext exists. There is no batch job that can do it — not
 * for this scheme, not for bcrypt, not for any password scheme ever designed.
 * Skip the upgrade and the user pays the legacy verification again on every
 * future login, which for the scrypt path is a measured 1.58 seconds, forever.
 *
 * {@see upgrade()} produces the replacement but does NOT store it, because
 * only the caller knows which table, which column and which transaction. A
 * contract that wrote to the database would need a repository, and this plugin
 * deliberately has none — it reads no tables and owns no schema.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT MUST NOT REACH THE USER
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Nothing from the verdict. "Your password is stored as an unsalted MD5" tells
 * an attacker which accounts are cheapest to crack offline; the refusal
 * reasons are written for an operator's log and the login response stays a
 * single generic failure for all of them.
 */
interface LegacyPasswordContract
{
    /**
     * Does this password match this legacy hash?
     *
     * Never throws for a wrong password — that is a refused verdict. Throws
     * only when the request itself is impossible to answer, which in practice
     * means a programming error rather than a credential problem.
     */
    public function verify(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): LegacyVerdict;

    /**
     * Recognise a hash that says what it is; null if it does not.
     *
     * Null is not a failure. It means the stored value is a BARE digest whose
     * algorithm, salt and parameters live somewhere this function cannot see,
     * so the caller must declare them through one of
     * {@see LegacyCredential}'s named constructors. Guessing is refused on
     * purpose — see {@see \Plugins\LegacyPasswords\Domain\HashDetector}.
     */
    public function detect(string $stored): ?LegacyCredential;

    /**
     * The modern replacement hash for a password that just verified.
     *
     * Delegates to the application's configured `HashingPort`, so the result
     * is whatever that project hashes new passwords with — never a second
     * opinion about cost or algorithm held by this plugin.
     */
    public function upgrade(#[\SensitiveParameter] string $password): string;

    /**
     * Which schemes THIS BUILD can actually verify.
     *
     * Not the same as the enum's cases: Argon2 needs it compiled in, the
     * Firebase path needs OpenSSL's AES-256-CTR, and plaintext needs enabling.
     * An importer should check this before a migration rather than discovering
     * a gap on the first login — which is why it is on the contract and not
     * buried in a config object.
     *
     * @return list<LegacyAlgorithm>
     */
    public function supported(): array;

    /** One safe line for a status page. No hashes, no salts, no keys. */
    public function describe(): string;
}
