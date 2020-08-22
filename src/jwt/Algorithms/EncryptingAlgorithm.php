<?php
namespace Itaiarbel\Jwt\Algorithms;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */

interface EncryptingAlgorithm
{
    // interface for algorithm types implemintations
    public static function encrypt($data, $key, $iv, &$tag);
    
    public static function decrypt($data, $key, $iv, &$tag);
    
    public static function auth_tag($header, $iv, $payload, $decrypted_key);
    
}