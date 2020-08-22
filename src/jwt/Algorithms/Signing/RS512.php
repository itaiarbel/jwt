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
class RS512 implements SigningAlgorithm
{

    const ALG = 'RS512';

    const DIGEST = 'sha512';

    static function sign($data, $private_key_or_secret)
    {
        openssl_sign($data, $signature, $private_key_or_secret, OPENSSL_ALGO_SHA512);
        return $signature;
    }

    static function verify($data, $public_key_or_secret, $signature)
    {
        return (boolean) openssl_verify($data, $signature, $public_key_or_secret, OPENSSL_ALGO_SHA512);
    }

}