<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

/**
 * Test for the core:AttributeLimit filter.
 *
 * @covers \SimpleSAML\Module\core\Auth\Process\AttributeLimit
 */
class SQL1CompatTest extends SQLTest
{
    protected string $wrapperClassName = '\SimpleSAML\Test\Module\sqlauth\Auth\Source\SQL1CompatWrapper';
}
