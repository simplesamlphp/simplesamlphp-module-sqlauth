<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\SQL1Compat::class)
class SQL1CompatTest extends SQLTest
{
    /**
     * @param array<mixed> $info
     * @param array<mixed> $config
     */
    protected function createWrapper(array $info, array $config): WrapperInterface
    {
        return new SQL1CompatWrapper($info, $config);
    }
}
