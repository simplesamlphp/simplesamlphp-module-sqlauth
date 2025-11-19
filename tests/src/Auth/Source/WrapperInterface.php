<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

interface WrapperInterface
{
    /**
     * @param array<mixed> $info
     * @param array<mixed> $config
     */
    public function __construct(array $info, array $config);


    /**
     * @return array<mixed>
     */
    public function callLogin(string $username, string $password): array;
}
