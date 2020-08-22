<?php
namespace Itaiarbel\Jwt;

use Itaiarbel\Jwt\Jwt;
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
class Jws
{

    // complete jwt encoded string
    var $jwt;

    // jwt header array
    var $header = array();

    // jwt claims array
    var $claims = array();

    // jwt signature
    var $signature = "";

    // verification status
    var $verified = false;

    function __construct($jwt_builder)
    {
        $this->jwt = $jwt_builder->jwt;
        $this->header = $jwt_builder->header;
        $this->claims = $jwt_builder->claims;

        if ($this->jwt != "") {
            $this->_decodeJWS($this->jwt);
        }

        return $this;
    }

    private function _encodeJWS()
    {
        // break the jws into 3 segments
        // base64 encode and build jwt from segments
        $segment_header = Helper::json_b64_encode((object) $this->header); // base64 header
        $segment_claims = Helper::json_b64_encode((object) $this->claims); // base64 claims
        $this->jwt = $segment_header . '.' . $segment_claims . '.' . $this->signature;
    }

    private function _decodeJWS()
    {
        // break the jwt segments
        $segments = explode('.', $this->jwt);

        if(!$segments || count($segments)!=3){
            throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');
        }
        
        // break the jws into 3 segments
        $this->header = Helper::json_b64_decode($segments[0]);
        $this->claims = Helper::json_b64_decode($segments[1]);
        $this->signature = $segments[2];
    }

    function sign($private_key_or_secret, $alg = 'HS256')
    {
        // Get algorithm class instance from string name $alg
        $SIGNER = Algorithms::signing($alg);

        $this->header = [
            'typ' => 'JWT',
            'alg' => $SIGNER::ALG
        ] + $this->header; // Modify header befor signing - add typ and alg
        $segment_header = Helper::json_b64_encode((object) $this->header); // Encode base64 header
        $segment_claims = Helper::json_b64_encode((object) $this->claims); // Encode base64 claims

        $this->signature = Helper::base64url_encode( // Base64url encode signiture        
        $SIGNER->sign( // Sign ;)
        $segment_header . '.' . $segment_claims, // "Header.Claims"
        $private_key_or_secret // Secret or Key
        ));
        $this->_encodeJWS(); // encode Jwt string property

        return $this;
    }

    function verify($public_key_or_secret, $alg = 'HS256')
    {
        // Get algorithm class instance from string name $alg
        $SIGNER = Algorithms::signing($alg);

        $segment_header = Helper::json_b64_encode((object) $this->header); // Base64 header string
        $segment_claims = Helper::json_b64_encode((object) $this->claims); // Base64 claims string

        $this->verified = $SIGNER->verify( // Verify ;)
        $segment_header . '.' . $segment_claims, // "header.claims"
        $public_key_or_secret, // Secret or Key
        Helper::base64url_decode($this->signature) // Base64 decoded signature
        );

        $this->_decodeJWS(); // encode Jwt string property

        return $this;
    }
}