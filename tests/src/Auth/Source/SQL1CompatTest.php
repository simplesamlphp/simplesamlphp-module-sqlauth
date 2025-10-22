<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

#CoversClass(SimpleSAML\Module\sqlauth\Auth\Source\SQL1Compat::class)
class SQL1CompatTest extends SQLTest
{
    protected string $wrapperClassName = '\SimpleSAML\Test\Module\sqlauth\Auth\Source\SQL1CompatWrapper';
}
