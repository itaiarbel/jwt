<?php
namespace Itaiarbel\Jwt\Algorithms\KeyEncrypting;

use Itaiarbel\Jwt\Algorithms\KeyEncryptingAlgorithm;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */
class RSA1_5 implements KeyEncryptingAlgorithm
{
    const ALG = 'RSA1_5';
    const ENC = '';
    const KEYBITS= 256;
    const DIGEST = '';

    static function encrypt($data, $private_key_or_secret)
    { 
        $key_size = self::get_key_bits_size($private_key_or_secret); //e.g 1024/2048/4096...
        
        $encrypted = '';
        $plainData = str_split($data, $key_size);
        foreach($plainData as $chunk)
        {
            $partial = '';
            if(openssl_private_encrypt($chunk, $partial, $private_key_or_secret, OPENSSL_PKCS1_PADDING)){
                $encrypted .= $partial;
            }else{
                return false;
            }
        }                  
        return base64_encode($encrypted);       
    }

    static function decrypt($data, $public_key_or_secret)
    {
        
        $key_size = self::get_key_bits_size($public_key_or_secret); //e.g 1024/2048/4096...

        $decrypted = '';        
        $plainData = str_split(base64_decode($data), $key_size);
        
        foreach($plainData as $chunk)
        {
            $partial = '';           
            if(openssl_public_decrypt($chunk, $partial, $public_key_or_secret, OPENSSL_PKCS1_PADDING)){
            $decrypted .= $partial;
            }else{
                return false;
            }
        }
        return $decrypted;        
    }
    
    
    private static function get_key_bits_size($key){
        $private_key=openssl_pkey_get_private ($key);
        $public_key=openssl_pkey_get_public ($key);
        
        if ($private_key){
            $key_info= openssl_pkey_get_details($private_key);
        }else if($public_key){
            $key_info= openssl_pkey_get_details($public_key);
        }else{
            return false; //invalid key
        }
        
        if (isset($key_info['bits'])){
            return $key_info['bits'];
        }else{
            return false; //can't resulve key
        }
    }
    
    
}