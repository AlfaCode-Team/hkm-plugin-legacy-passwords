<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HashingPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\LegacyPasswords\API\Contracts\LegacyPasswordContract;
use Plugins\LegacyPasswords\Application\Services\LegacyPasswordService;
use Plugins\LegacyPasswords\Infrastructure\Cli\InspectHashCommand;
use Plugins\LegacyPasswords\Infrastructure\Config\LegacyPasswordConfig;

/**
 * Legacy passwords — wires the 'password.legacy' domain.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * WHY THIS IS NOT PART OF THE CRYPTO PLUGIN
 * ════════════════════════════════════════════════════════════════════════════
 *
 * `crypto.services` would have been the obvious home: it owns `HashingPort`,
 * it needs no database, and an importer depends on it anyway. It was rejected
 * for one reason that outweighs the convenience.
 *
 * EVERY PROJECT LOADS crypto.services, because it is how passwords are hashed.
 * Putting MD5, unsalted SHA and plaintext verification in there would mean
 * every application everywhere carries code that can check a password against
 * an unsalted MD5 — and that a security review of the plugin which defines
 * "how we hash passwords" has to reason about nine deliberately weak schemes
 * that project will never use.
 *
 * Here they are in a module a project only loads if it is migrating off
 * something, which is both honest about the dependency and a smaller blast
 * radius. Nothing in `crypto.services` can reach a weak algorithm, because the
 * weak algorithms are not in it.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * NO ROUTES, NO TABLE, NO MIGRATION
 * ────────────────────────────────────────────────────────────────────────────
 *
 * This plugin reads nothing and writes nothing. It answers one question about
 * one string, and the caller owns the user table, the transaction and the
 * decision about who may log in.
 *
 * An HTTP route would be actively wrong: `POST /legacy/verify` taking a
 * password and a hash is an oracle for testing passwords against arbitrary
 * hashes at the server's expense — which is both a password-cracking service
 * and, at 1.58 seconds per scrypt call, a denial of service with a one-line
 * request.
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'password.legacy';
    }

    /** @return list<string> */
    public function requires(): array
    {
        // crypto.services for HashingPort — the replacement hash is minted
        // with the APPLICATION's hasher, never with an opinion held here.
        return ['crypto.services'];
    }

    /** @return list<class-string> */
    public function exposes(): array
    {
        return [LegacyPasswordContract::class];
    }

    public function register(ModuleContainer $container): void
    {
        $container->bindInternal(
            LegacyPasswordConfig::class,
            static fn (): LegacyPasswordConfig => LegacyPasswordConfig::fromEnv(),
        );

        $container->bind(
            LegacyPasswordContract::class,
            static fn (ModuleContainer $c): LegacyPasswordService => new LegacyPasswordService(
                config: $c->make(LegacyPasswordConfig::class),
                hasher: $c->make(HashingPort::class),
                // Optional. `has()` rather than a try/catch, because a project
                // without a logger adapter is an ordinary configuration and
                // not an exceptional one — and a missing logger must never
                // stop a login working.
                logger: $c->has(LoggerPort::class) ? $c->make(LoggerPort::class) : null,
            ),
        );
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        // No HTTP hook and no route filter. There is nothing to run on every
        // request: a legacy verification happens inside a login, which is the
        // auth module's business, and a filter that intercepted logins would
        // have to know that module's request shape.
        //
        // The command is DEFERRED and registered as an INSTANCE. Both matter:
        //
        //  • boot() also runs during an HTTP build, and nothing here should be
        //    constructed on a path that will never use it;
        //  • a command registered by CLASS-STRING is built from the
        //    CoreContainer, and LegacyPasswordContract is bound per REQUEST.
        //    Reflection cannot autowire it from the core, and the failure is
        //    silent — the command simply never appears in `list`, which looks
        //    exactly like the plugin not being installed.
        $cli->defer(static function (CliPipeline $cli): void {
            $cli->command(new InspectHashCommand(self::forCli($cli->container())));
        });
    }

    /**
     * The service the CLI operates on.
     *
     * `HashingPort` is an app-lifetime port, so it resolves from the core
     * directly. There is a fallback for the case where a project wired it only
     * into the request container: the command's job is to INSPECT and VERIFY,
     * and neither needs the hasher — only `upgrade()` does, which the command
     * never calls. Refusing to register over a dependency the command cannot
     * use would hide the diagnostic tool exactly when an import is going
     * wrong.
     */
    private static function forCli(CoreContainer $core): LegacyPasswordService
    {
        return new LegacyPasswordService(
            config: LegacyPasswordConfig::fromEnv(),
            hasher: $core->has(HashingPort::class) ? $core->make(HashingPort::class) : null,
            logger: $core->has(LoggerPort::class) ? $core->make(LoggerPort::class) : null,
        );
    }
}
