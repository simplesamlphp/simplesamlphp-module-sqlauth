<?php

declare(strict_types=1);

namespace SimpleSAML\Module\sqlauth\Auth\Source;

use Exception;
use PDO;
use PDOException;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\sqlauth\Auth\Source\SQL;

use function array_key_exists;
use function array_keys;
use function count;
use function implode;
use function in_array;
use function is_null;
use function password_verify;
use function sprintf;
use function strval;

/**
 * Simple SQL authentication source
 *
 * This class is very much like the SQL class. The major difference is that
 * instead of using SHA2 and other functions in the database we use the PHP
 * password_verify() function to allow for example PASSWORD_ARGON2ID to be used
 * for verification.
 *
 * While this class has a query parameter as the SQL class does the meaning
 * is different. The query for this class should return at least a column
 * called passwordhash containing the hashed password which was generated
 * for example using
 *    password_hash('hello', PASSWORD_ARGON2ID );
 *
 * Auth only passes if the PHP code below returns true.
 *   password_verify($password, row['passwordhash'] );
 *
 * Unlike the SQL class the username is the only parameter passed to the SQL query,
 * the query can not perform password checks, they are performed by the PHP code
 * in this class using password_verify().
 *
 * If there are other columns in the returned data they are assumed to be attributes
 * you would like to be returned through SAML.
 *
 * @package SimpleSAMLphp
 */

class PasswordVerify extends SQL
{
    /**
     * The column in the result set containing the passwordhash.
     */
    protected string $passwordhashcolumn = 'passwordhash';

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (array_key_exists('passwordhashcolumn', $config)) {
            $this->passwordhashcolumn = $config['passwordhashcolumn'];
        }
    }



    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a \SimpleSAML\Error\Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login(string $username, string $password): array
    {
        $this->verifyUserNameWithRegex( $username );
        
        $db = $this->connect();
        $params = ['username' => $username, 'password' => $password];
        $attributes = [];

        $numQueries = count($this->query);
        for ($x = 0; $x < $numQueries; $x++) {

            $data = $this->executeQuery( $this->query[$x], $params )
            
            \SimpleSAML\Logger::info('sqlauth:'.$this->authId.': Got '.count($data).
                                     ' rows from database');

            if ($x === 0) {
                if (count($data) === 0) {
                    // No rows returned - invalid username/password
                    \SimpleSAML\Logger::error('sqlauth:'.$this->authId.
                                              ': No rows in result set. Probably wrong username/password.');
                    throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
                }
                /* Only the first query should be passed the password, as that is the only
                 * one used for authentication. Subsequent queries are only used for
                 * getting attribute lists, so only need the username. */
                unset($params['password']);
            }
                

            /**
             * Sanity check, passwordhash must be in each resulting tuple and must have
             * the same value in every tuple.
             * 
             * Note that $pwhash will contain the passwordhash value after this loop.
             */
            $pwhash = null;
            foreach ($data as $row) {
                if (!array_key_exists($this->passwordhashcolumn, $row)
                    || is_null($row[$this->passwordhashcolumn]))
                {
                    \SimpleSAML\Logger::error('sqlauth:'.$this->authId.
                                              ': column ' . $this->passwordhashcolumn . ' must be in every result tuple.');
                    throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
                }
                if( $pwhash ) {
                    if( $pwhash != $row[$this->passwordhashcolumn] ) {
                        \SimpleSAML\Logger::error('sqlauth:'.$this->authId.
                                                  ': column ' . $this->passwordhashcolumn . ' must be THE SAME in every result tuple.');
                        throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
                    }
                }
                $pwhash = $row[$this->passwordhashcolumn];
            }
            /**
             * This should never happen as the count(data) test above would have already thrown.
             * But checking twice doesn't hurt.
             */
            if( is_null($pwhash)) {
                if( $pwhash != $row[$this->passwordhashcolumn] ) {
                    \SimpleSAML\Logger::error('sqlauth:'.$this->authId.
                                              ': column ' . $this->passwordhashcolumn . ' does not contain a password hash.');
                    throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
                }
            }

            /**
             * VERIFICATION!
             * Now to check if the password the user supplied is actually valid
             */
            if( !password_verify( $password, $pwhash )) {
                \SimpleSAML\Logger::error('sqlauth:'.$this->authId. ': password is incorrect.');
                throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
            }


            $this->extractAttributes( $attributes, $data, array($this->passwordhashcolumn) );
        }
        
        \SimpleSAML\Logger::info('sqlauth:'.$this->authId.': Attributes: '.
            implode(',', array_keys($attributes)));

        return $attributes;
    }
}
