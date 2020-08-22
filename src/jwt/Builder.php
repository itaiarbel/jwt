<?php
namespace Itaiarbel\Jwt;

use Itaiarbel\Jwt\Helper;
use Itaiarbel\Jwt\Jws;
use Itaiarbel\Jwt\Jwe;

/**
 * JwtBuilder - Build your token before signing/encrypting it
 *
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */

class JwtBuilder extends Jwt
{
    
    var $jwt;
    
    // complete jwt encoded string
    var $header = array();
    
    // jwt header array
    var $claims = array();
    
    
    function __construct($jwt_string=""){
        if ($jwt_string != "") {
            $this->jwt= $jwt_string;
        }        
    }
    
    public function sign($private_key_or_secret, $alg = 'HS256'){        
        $jws=  new Jws($this);
        $jws->sign($private_key_or_secret, $alg);
        $this->jwt = $jws->jwt; //signed jwt
        return $this;             
    }

    public function encrypt($private_key_or_secret, $alg = 'RSA1_5', $enc="A218CBC-HS256"){
        $jwe = new Jwe($this);        
        $this->jwt = $jwe->jwt; //signed jwt        
        return $jwe->encrypt($private_key_or_secret, $alg, $enc);
     
    }
    
      /* 
    
    function header($claim, $value)
    {
        // add header to jwt
        $this->header[$claim] = $value;
                
        return $this;
    }*/
    
    function header($claim, $value, $override_existing = false)
    {
        // add claim to jwt header
        if (! isset($this->header[$claim])) {
            $this->header[$claim] = $value; // add to header
        } else { // claim exist
            if ($override_existing) { // add claim only if user add override
                $this->header[$claim] = $value;
            }
        }
        return $this;
    }
    

    
    function claim($claim, $value, $override_existing = false)
    {
        // add claim to jwt
        if (! isset($this->claims[$claim])) {
            $this->claims[$claim] = $value; // add to claim
        } else { // claim exist
            if ($override_existing) { // add claim only if user add override
                $this->claims[$claim] = $value;
            }
        }
        return $this;
    }

    function claims($claims_array, $override_existing = false)
    {
        // add claims as array
        if ($override_existing) { // if user select to override
            foreach ($claims_array as $key => $claim) {
                if (isset($this->claims[$key])) { // override claims if exist
                    $this->claims[$key] = $claim;
                }
            }
        }
        // appending the rest of the claims to the end to the claims array
        $this->claims = $this->claims + $claims_array;
        return $this;
    }

    function exp($exp_in_sec, $now = 0)
    {
        // adds issue time and exp to claims, recived exp in seconds and now= current server ts / user ts
        if ($now == 0) {
            $now = time();
        }
        $this->claim('iat', $now, true);
        $this->claim('exp', $now + $exp_in_sec, true);
        return $this;
    }

    function nbf($exp_in_sec, $now = 0)
    {
        if ($now == 0) {
            $now = time();
        }
        $this->claim('nbf', $now + $exp_in_sec, true);
        return $this;
    }

    function jti()
    {
        // adds a random guid jti to claims
        $this->jti = Helper::guid();
        $this->claim('jti', $this->jti, true);
        return $this;
    }
    
    function iss($issuer)
    {
        // adds iss claim
        $this->claim('iss', $issuer, true);
        return $this;
    }
    function issuer($issuer)
    {
        // adds iss claim
        $this->claim('iss', $issuer, true);
        return $this;
    }
    
    
    
}

?>