<?php

declare(strict_types=1);

namespace SimpleSAML\Module\sqlauth\Auth\Source;

/**
 * @package SimpleSAMLphp
 */

class SQL1Compat extends SQL2
{
    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        /* Transform SQL (version 1) config to SQL2 config
         * Version 1 supported only one database, but multiple queries. The first query was defined
         * to be the "authentication query", all subsequent queries were "attribute queries".
         */
        $v2config = [
            'sqlauth:SQL2',
            'databases' => [
                'default' => [
                    'dsn' => $config['dsn'],
                    'username' => $config['username'],
                    'password' => $config['password'],
                ],
            ],

            'auth_queries' => [
                'default' => [
                    'database' => 'default',
                    'query' => is_array($config['query']) ? $config['query'][0] : $config['query'],
                ],
            ],
        ];

        if (array_key_exists('username_regex', $config)) {
            $v2config['auth_queries']['default']['username_regex'] = $config['username_regex'];
        }

        $numQueries = is_array($config['query']) ? count($config['query']) : 0;
        if ($numQueries > 1) {
            $v2config['attr_queries'] = [];
            for ($i = 1; $i < $numQueries; $i++) {
                $v2config['attr_queries']['query' . $i] = [
                    'database' => 'default',
                    'query' => $config['query'][$i],
                ];
            }
        }

        // Copy other config keys that are not specific to SQL1 (eg. core:login_links)
        foreach (array_keys($config) as $key) {
            if (in_array($key, ['dsn', 'username', 'password', 'query', 'username_regex'])) {
                continue;
            }

            $v2config[$key] = $config[$key];
        }

        parent::__construct($info, $v2config);
    }
}
