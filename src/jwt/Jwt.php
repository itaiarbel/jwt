<?php
namespace Itaiarbel\Jwt;

use Itaiarbel\Jwt\Jws;
use Itaiarbel\Jwt\Jwe;
use Itaiarbel\Jwt\Helper;
use Itaiarbel\Jwt\Exceptions;
use Itaiarbel\Jwt\Algorithms;
use Itaiarbel\Jwt\JwtBuilder;
use Itaiarbel\Jwt\JwtChecker;


/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */

class Jwt
{

    // helps you build tokens
    public static function Builder($jwt_string = "")
    {
        return new JwtBuilder($jwt_string);
    }

    // helps you check tokens
    public static function Checker($jwt_string = "")
    {
        return new JwtChecker($jwt_string);
    }


    // helps you manage keys    
    public static function KeysManager()
    {
        //key manager  generate keys/ store keys/ find keys 
        //return new JwtKeysManager(); //:TODO
        return false;
    }
    
}
