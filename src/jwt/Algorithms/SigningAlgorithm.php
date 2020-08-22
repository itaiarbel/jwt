<?php
namespace Itaiarbel\Jwt\Algorithms;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */

interface SigningAlgorithm
{
    // interface for algorithm types implemintations
    public static function sign($data, $private_key_or_secret);
    
    public static function verify($data, $public_key_or_secret, $signature);
}
