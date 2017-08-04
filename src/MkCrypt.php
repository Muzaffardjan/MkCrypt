<?php
/**
 * PHP Password hash for Zend framework
 *
 * @author    Muzaffardjan Karaev
 * @copyright Copyright (c) "FOR EACH SOFT" LTD 2015 (http://www.each.uz)
 * @license   "FOR EACH SOFT" LTD PUBLIC LICENSE
 * Created:   04.08.2017
 */

namespace MkCrypt;

use MkCrypt\Exception\InvalidArgumentException;
use MkCrypt\Exception\RuntimeException;
use Zend\Stdlib\ArrayUtils;
use Zend\Math\Rand;

class MkCrypt
{
    const MIN_SALT_SIZE = 16;

    /**
     * @var mixed|string
     */
    protected $cost = '10';

    /**
     * @var mixed
     */
    protected $salt;

    public function __construct(array $options = [])
    {
        if ($options instanceof \Traversable) {
            $options = ArrayUtils::iteratorToArray($options);
        } elseif (!is_array($options)) {
            throw new InvalidArgumentException(
                'The options parameter must be an array or a Traversable'
            );
        }

        foreach ($options as $key => $option) {
            switch (strtolower($key)) {
                case 'salt':
                    $this->salt = $option;
                    break;
                case 'cost':
                    $this->cost = $option;
                    break;
            }
        }
    }

    public function create($string)
    {
        if (empty($this->salt)) {
            $this->salt = Rand::getBytes(self::MIN_SALT_SIZE);
        }

        $salt64 = substr(
            str_replace('+','.',base64_encode($this->salt)),
            0,
            22
        );

        $hash = password_hash(
            $string,
            PASSWORD_BCRYPT,
            [
                'cost' => $this->cost,
                'salt' => $salt64
            ]
        );

        if (strlen($hash) < 13) {
            throw new RuntimeException('Error during the bcrypt generation');
        }

        return $hash;
    }

    public function verify($password, $hash)
    {
        $password = (string) $password;
        $hash     = (string) $hash;

        if (function_exists('password_verify')) {
            return password_verify($password, $hash);
        }

        $lengthPassword = strlen($password);
        $lengthHash     = strlen($hash);
        $minLength      = min($lengthHash, $lengthPassword);
        $result         = 0;

        for ($i = 0; $i < $minLength; $i++) {
            $result |= ord($password[$i]) ^ ord($hash[$i]);
        }

        $result |= $lengthPassword ^ $lengthHash;

        return ($result === 0);
    }
}