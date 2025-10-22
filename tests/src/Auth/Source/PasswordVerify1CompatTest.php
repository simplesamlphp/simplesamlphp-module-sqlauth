<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\PasswordVerify1Compat::class)
class PasswordVerify1CompatTest extends PasswordVerifyTest
{
    protected string $wrapperClassName = '\SimpleSAML\Test\Module\sqlauth\Auth\Source\PasswordVerify1CompatWrapper';
}
