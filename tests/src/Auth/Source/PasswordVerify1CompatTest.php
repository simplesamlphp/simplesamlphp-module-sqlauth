<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

/**
 * Test for the core:AttributeLimit filter.
 *
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class PasswordVerify1CompatTest extends PasswordVerifyTest
{
    protected string $wrapperClassName = '\SimpleSAML\Test\Module\sqlauth\Auth\Source\PasswordVerify1CompatWrapper';
}
