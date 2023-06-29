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
    protected ?string $passwordhashcolumn = null;

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

        if ($this->passwordhashcolumn === null) {
            $this->passwordhashcolumn = 'passwordhash';
        }
    }


    /**
     * Extract SQL columns into SAML attribute array
     *
     * @param array  $data  Associative array from database in the format of PDO fetchAll
     * @param array  $forbiddenAttributes An array of attributes to never return
     * @return array  Associative array with the users attributes.
     */
    protected function extractAttributes( $data, $forbiddenAttributes = array() )
    {
        $attributes = [];
        foreach ($data as $row) {
            foreach ($row as $name => $value) {
                if ($value === null) {
                    continue;
                }
                if (in_array($name, $forbiddenAttributes)) {
                    continue;
                }
               

                $value = strval($value);

                if (!array_key_exists($name, $attributes)) {
                    $attributes[$name] = [];
                }

                if (in_array($value, $attributes[$name], true)) {
                    // Value already exists in attribute
                    continue;
                }

                $attributes[$name][] = $value;
            }
        }
        
        return $attributes;
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
        $db = $this->connect();
        
        try {
            $sth = $db->prepare($this->query);
        } catch (PDOException $e) {
            throw new Exception(sprintf(
                'sqlauth:%s: - Failed to prepare query: %s',
                $this->authId,
                $e->getMessage(),
            ));
        }


        try {
            $sth->execute(['username' => $username]);
        } catch (PDOException $e) {
            throw new Exception(sprintf(
                'sqlauth:%s: - Failed to execute sql: %s query: %s',
                $this->authId,
                $this->query,
                $e->getMessage(),
            ));
        }

        try {
            $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            throw new Exception(sprintf(
                'sqlauth:%s: - Failed to fetch result set: %s',
                $this->authId,
                $e->getMessage(),
            ));
        }

        Logger::info(sprintf(
            'sqlauth:%s : Got %d rows from database',
            $this->authId,
            count($data),
        ));

        if (count($data) === 0) {
            // No rows returned - invalid username/password
            Logger::error(sprintf(
                'sqlauth:%s: No rows in result set. Probably wrong username/password.',
                $this->authId,
            ));
            throw new Error\Error('WRONGUSERPASS');
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
                Logger::error(sprintf(
                    'sqlauth:%s: column %s must be in every result tuple.',
                    $this->authId,
                    $this->passwordhashcolumn,
                ));
                throw new Error\Error('WRONGUSERPASS');
            }
            if ($pwhash) {
                if ($pwhash !== $row[$this->passwordhashcolumn]) {
                    Logger::error(sprintf(
                        'sqlauth:%s: column %s must be THE SAME in every result tuple.',
                        $this->authId,
                        $this->passwordhashcolumn,
                    ));
                    throw new Error\Error('WRONGUSERPASS');
                }
            }
            $pwhash = $row[$this->passwordhashcolumn];
        }
        /**
         * This should never happen as the count(data) test above would have already thrown.
         * But checking twice doesn't hurt.
         */
        if (is_null($pwhash)) {
            if ($pwhash !== $row[$this->passwordhashcolumn]) {
                Logger::error(sprintf(
                    'sqlauth:%s: column %s does not contain a password hash.',
                    $this->authId,
                    $this->passwordhashcolumn,
                ));
                throw new Error\Error('WRONGUSERPASS');
            }
        }

        /**
         * VERIFICATION!
         * Now to check if the password the user supplied is actually valid
         */
        if (!password_verify($password, $pwhash)) {
            Logger::error(sprintf('sqlauth:%s: password is incorrect.', $this->authId));
            throw new Error\Error('WRONGUSERPASS');
        }

        
        $attributes = $this->extractAttributes($data, [$this->passwordhashcolumn]);

        Logger::info(sprintf(
            'sqlauth:%s: Attributes: %s',
            $this->authId,
            implode(',', array_keys($attributes)),
        ));

        return $attributes;
    }
}
