<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Support;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;

/**
 * A `LoggerPort` that keeps every line, with its level.
 *
 * The level is what the tests actually assert on, and it carries a real
 * requirement: an OPERATIONAL refusal has to be an error, because it means a
 * whole population cannot log in and nobody has been told, while a wrong
 * password has to be debug, because it happens thousands of times a day and
 * would otherwise bury the thing that matters.
 *
 * It also lets a test assert the NEGATIVE that matters most — that no logged
 * line ever contains the password or the hash.
 */
final class RecordingLogger implements LoggerPort
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    public array $lines = [];

    public function emergency(string|\Stringable $message, array $context = []): void
    {
        $this->log('emergency', $message, $context);
    }

    public function alert(string|\Stringable $message, array $context = []): void
    {
        $this->log('alert', $message, $context);
    }

    public function critical(string|\Stringable $message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    public function error(string|\Stringable $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    public function warning(string|\Stringable $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    public function notice(string|\Stringable $message, array $context = []): void
    {
        $this->log('notice', $message, $context);
    }

    public function info(string|\Stringable $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    public function debug(string|\Stringable $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    public function log(string $level, string|\Stringable $message, array $context = []): void
    {
        $this->lines[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
    }

    /** @return list<string> */
    public function messagesAt(string $level): array
    {
        return array_values(array_map(
            static fn (array $line): string => $line['message'],
            array_filter($this->lines, static fn (array $line): bool => $line['level'] === $level),
        ));
    }

    /** Every message and every scalar context value, concatenated. */
    public function everything(): string
    {
        $out = '';

        foreach ($this->lines as $line) {
            $out .= $line['message'] . ' ';

            foreach ($line['context'] as $key => $value) {
                $out .= $key . '=' . (\is_scalar($value) ? (string) $value : '?') . ' ';
            }
        }

        return $out;
    }
}
