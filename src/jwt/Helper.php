<?php
namespace Itaiarbel\Jwt;

use Itaiarbel\Jwt\Exceptions;

class Helper
{

    public static function json_b64_encode($object)
    {
        // base64 encode json
        $encoded_json= json_encode($object);
        if (!$encoded_json){throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');}
        return self::base64url_encode($encoded_json);      
    }

    public static function json_b64_decode($object)
    {
        // base64 decode json
        $decoded_json = json_decode(self::base64url_decode($object), true);
        if (!$decoded_json){throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');}
        return $decoded_json;        
    }

    public static function base64url_encode($data)
    {
        if ($data=="") {return "";}
        // Encode data to Base64URL
        $b64 = base64_encode($data);
        if (!$b64){throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');}
        $url = strtr($b64, '+/', '-_');
        return rtrim($url, '=');
    }

    public static function base64url_decode($data, $strict = false)
    {
        if ($data=="") {return "";}
        // Decode data from Base64URL
        $b64 = strtr($data, '-_', '+/');
        $decoded=base64_decode($b64, $strict);
        if (!$decoded){throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');}
        return $decoded;        
    }

    public static function guid()
    {
        // Get an RFC-4122 compliant globaly unique identifier
        $data = PHP_MAJOR_VERSION < 7 ? openssl_random_pseudo_bytes(16) : random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // Set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // Set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}