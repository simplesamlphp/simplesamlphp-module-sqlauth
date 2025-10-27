<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\sqlauth\Auth\Source;

use SimpleSAML\Module\sqlauth\Auth\Source\PasswordVerify;

/**
 * This class only exists to allow us to call the protected login() method.
 * The calling method in UserPassBase.php doesn't return, so can't be used
 * from PHPUnit. So we do this just to be able to unit test the login()
 * method in PasswordVerify.php
 */

class PasswordVerifyWrapper extends PasswordVerify implements WrapperInterface
{
    /**
     * @param array<mixed> $info
     * @param array<mixed> $config
     */
    public function __construct(array $info, array $config)
    {
        parent::__construct($info, $config);
    }


    /**
     * @return string[]
     */
    public function callLogin(string $username, string $password): array
    {
        return $this->login($username, $password);
    }
}
