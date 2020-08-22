<?php
namespace Itaiarbel\Jwt;

use Itaiarbel\Jwt\Exceptions;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */

class Algorithms
{

    // all available Signing algoritms registered here
    // alg in header of JWS
    static $signing = [
        'NONE' => Algorithms\Signing\NONE::class,
        'HS256' => Algorithms\Signing\HS256::class,
        'HS384' => Algorithms\Signing\HS384::class,
        'HS512' => Algorithms\Signing\HS512::class,
        'RS256' => Algorithms\Signing\RS256::class,
        'RS384' => Algorithms\Signing\RS384::class,
        'RS512' => Algorithms\Signing\RS512::class
        // 'ES256' => Algorithms\Signing\ES256::class, //TODO
        // 'ES384' => Algorithms\Signing\ES384::class, //TODO
        // 'ES512' => Algorithms\Signing\ES512::class, //TODO
        // 'PS256' => Algorithms\Signing\PS256::class, //TODO
        // 'PS384' => Algorithms\Signing\PS384::class, //TODO
        // 'PS512' => Algorithms\Signing\PS512::class, //TODO
    ];

    // all available Key Encrypting algoritms registered here
    // alg in header of JWE
    static $key_encrypting = [
        'RSA1_5' => Algorithms\KeyEncrypting\RSA1_5::class
        // 'RSA-OAEP' => Algorithms\KeyEncrypting\RSA_OAEP::class, //TODO
        // 'RSA-OAEP-256' => Algorithms\KeyEncrypting\RSA_OAEP_256::class, //TODO
        // 'A128KW' => Algorithms\KeyEncrypting\A128KW::class, //TODO
        // 'A192KW' => Algorithms\KeyEncrypting\A192KW::class, //TODO
        // 'A256KW' => Algorithms\KeyEncrypting\A192KW::class, //TODO
        // 'dir' => Algorithms\KeyEncrypting\dir::class, //TODO
        // 'ECDH-ES' => Algorithms\KeyEncrypting\ECDH_ES::class, //TODO
        // 'ECDH-ES+A128KW' => Algorithms\KeyEncrypting\ECDH_ES_A128KW::class, //TODO
        // 'ECDH-ES+A192KW' => Algorithms\KeyEncrypting\ECDH_ES_A192KW::class, //TODO
        // 'ECDH-ES+A256KW' => Algorithms\KeyEncrypting\ECDH_ES_A256KW::class, //TODO
        // 'A128GCMKW' => Algorithms\KeyEncrypting\A128GCMKW::class, //TODO
        // 'A192GCMKW' => Algorithms\KeyEncrypting\A192GCMKW::class, //TODO
        // 'A256GCMKW' => Algorithms\KeyEncrypting\A256GCMKW::class, //TODO
        // 'PBES2-HS256+A128KW' => Algorithms\KeyEncrypting\PBES2_HS256_A128KW::class, //TODO
        // 'PBES2-HS384+A192KW' => Algorithms\KeyEncrypting\PBES2_HS384_A192KW::class, //TODO
        // 'PBES2-HS512+A256KW' => Algorithms\KeyEncrypting\PBES2_HS512_A256KW::class, //TODO
    ];

    // all available Encrypting algoritms registered here
    // enc in header of JWE
    static $encrypting = [
        'A128CBC-HS256' => Algorithms\Encrypting\A128CBC_HS256::class,
        'A192CBC-HS384' => Algorithms\Encrypting\A192CBC_HS384::class,
        'A256CBC-HS512' => Algorithms\Encrypting\A256CBC_HS512::class,
        'A128GCM'       => Algorithms\Encrypting\A128GCM::class,
        'A192GCM'       => Algorithms\Encrypting\A192GCM::class,
        'A256GCM'       => Algorithms\Encrypting\A256GCM::class,
    ];

    // get the algorithm class from user input string
    public static function signing($alg_string = "HS256")
    {
        $alg_string = strtoupper($alg_string);
        if (isset(self::$signing[$alg_string])) {
            return new self::$signing[$alg_string](); // algorithm class
        } else {
            // algorithm not found exception
            throw new Exceptions\Exception_AlgorithmNotFound('Algorithm \'' . $alg_string . '\' not found.');
        }
    }


    // get the algorithm class from user input string
    public static function key_encrypting($alg_string = "RSA1_5")
    {
        $alg_string = strtoupper($alg_string);
        if (isset(self::$key_encrypting[$alg_string])) {
            return new self::$key_encrypting[$alg_string](); // algorithm class
        } else {
            // algorithm not found exception
            throw new Exceptions\Exception_AlgorithmNotFound('Algorithm \'' . $alg_string . '\' not found.');
        }
    }
    
    // get the algorithm class from user input string
    public static function encrypting($alg_string = "A128CBC-H256")
    {
        $alg_string = strtoupper($alg_string);
        if (isset(self::$encrypting[$alg_string])) {
            return new self::$encrypting[$alg_string](); // algorithm class
        } else {
            // algorithm not found exception
            throw new Exceptions\Exception_AlgorithmNotFound('Algorithm \'' . $alg_string . '\' not found.');
        }
    }
}

