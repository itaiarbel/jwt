<?php
namespace Itaiarbel\Jwt\Algorithms\Signing;

use Itaiarbel\Jwt\Algorithms\SigningAlgorithm;
use Itaiarbel\Jwt\Exceptions\Exception_AlgorithmNone;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */
class NONE implements SigningAlgorithm
{

    const ALG = 'none';

    const DIGEST = '';

    static function sign($data, $private_key_or_secret)
    {
        return '';  //build a not signed jwt
    }

    static function verify($data, $public_key_or_secret, $signature)
    {
        throw new Exception_AlgorithmNone('Algorithm NONE cannot be verified for security reasons.');
    }
  
}