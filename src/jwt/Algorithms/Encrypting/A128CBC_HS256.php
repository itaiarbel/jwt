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
class A128CBC_HS256 implements EncryptingAlgorithm
{
    const ENC = 'A128CBC-HS256';    
    const IVBITSLENGTH = 128;       
    const KEYBITSLENGTH = 256;
    const DIGEST = 'sha256';

    static function encrypt($data, $key, $iv, &$tag)
    {    
        $tag=null; // -> force jwe class to call auth_tag()
        return openssl_encrypt($data, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    static function decrypt($data, $key, $iv, &$tag)
    {
        $tag=null; // -> force jwe class to call auth_tag()
        return openssl_decrypt($data, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);         
    }
    
    static function auth_tag($header, $iv, $payload, $decrypted_key)
    {
        $hash_key = mb_substr($decrypted_key, 0, mb_strlen($decrypted_key, '8bit') / 2, '8bit');
        $header_length = mb_strlen($header, '8bit');
        $data = implode('', [
            $header,
            $iv,
            $payload,
            pack('N2', ($header_length / 2147483647) * 8, ($header_length % 2147483647) * 8),
        ]);
        $hash = hash_hmac(self::DIGEST, $data, $hash_key, true);
        return  mb_substr($hash, 0, mb_strlen($hash, '8bit') / 2, '8bit');
    }
    
}