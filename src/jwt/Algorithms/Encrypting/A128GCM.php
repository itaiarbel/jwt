<?php
namespace Itaiarbel\Jwt\Algorithms\Encrypting;

use Itaiarbel\Jwt\Algorithms\EncryptingAlgorithm;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */
class A128GCM implements EncryptingAlgorithm
{
    const ENC = 'A128GCM';    
    const IVBITSLENGTH = 96;       
    const KEYBITSLENGTH = 128;  
    const DIGEST = '';

    static function encrypt($data, $key, $iv, &$tag)
    {    
        return openssl_encrypt($data, 'aes-128-gcm', $key, $options=0, $iv, $tag);
    }

    static function decrypt($data, $key, $iv, &$tag)
    {
        return openssl_decrypt($data, 'aes-128-gcm', $key, $options=0, $iv, $tag);         
    }
    
    static function auth_tag($header, $iv, $payload, $decrypted_key)
    {        
        return false;
    }
    
}