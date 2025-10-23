<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\PasswordVerify1Compat::class)
class PasswordVerify1CompatTest extends PasswordVerifyTest
{
    /**
     * @param array<mixed> $info
     * @param array<mixed> $config
     */
    protected function createWrapper(array $info, array $config): WrapperInterface
    {
        return new PasswordVerify1CompatWrapper($info, $config);
    }
}
