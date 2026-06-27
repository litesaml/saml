<?php

namespace Litesaml\Models\Descriptors;

abstract readonly class Key
{
    public function __construct(public string $value) {}

    /** @return array{start: string, end: string} */
    abstract protected function getHeaders(): array;

    public function toPem(): string
    {
        $headers = $this->getHeaders();

        $pattern = '/^' . $headers['start'] . '([^-]*)^' . $headers['end'] . '/m';

        if (preg_match($pattern, $this->value)) {
            return $this->value;
        }

        $data = chunk_split($this->value, 64, "\n");

        return $headers['start'] . "\n" . $data . $headers['end'] . "\n";
    }
}
