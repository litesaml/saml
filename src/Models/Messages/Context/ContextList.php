<?php

namespace Litesaml\Models\Messages\Context;

use Litesaml\Exceptions\SamlException;

final class ContextList
{
    /** @var array<class-string<Context>, Context[]> */
    private array $items = [];

    public function __construct(Context ...$items)
    {
        foreach ($items as $item) {
            $this->items[$item::class][] = $item;
        }
    }

    /**
     * @template T of Context
     *
     * @param class-string<T> $class
     *
     * @return T[]
     */
    public function all(string $class): array
    {
        return $this->items[$class] ?? [];
    }

    /**
     * @template T of Context
     *
     * @param class-string<T> $class
     *
     * @return T|null
     */
    public function first(string $class): ?Context
    {
        return $this->items[$class][0] ?? null;
    }

    /**
     * @template T of Context
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    public function required(string $class, string $message): Context
    {
        return $this->first($class) ?? throw new SamlException($message);
    }
}
