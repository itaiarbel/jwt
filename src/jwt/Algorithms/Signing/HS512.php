<?php
namespace Itaiarbel\Jwt\Algorithms\Signing;

use Itaiarbel\Jwt\Algorithms\SigningAlgorithm;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */
class HS512 implements SigningAlgorithm
{
    
    const ALG = 'HS512';
    
    const DIGEST = 'sha512';
    
    static function sign($data, $private_key_or_secret)
    {
        return hash_hmac(self::DIGEST, $data, $private_key_or_secret, true);
    }
    
    static function verify($data, $public_key_or_secret, $signature)
    {
        return (hash_hmac(self::DIGEST, $data, $public_key_or_secret, true) == $signature);
    }
    
}