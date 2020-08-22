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

class Jwe extends Jwt
{

    // complete jwt encoded string
    var $jwt;

    // jwt header array
    var $header = array();

    // jwt claims array
    var $claims = array();

    //encryptedkey from jwt
    var $encrypted_key = "";

    // key after decryption
    var $decrypted_key = "";
    
    //inialization vector
    var $iv = "";

    //encrypted claims
    var $payload = "";

    //authenticating tag
    var $tag = "";

    //decryption indication for checker class
    var $decrypted = false;
    

    function __construct($jwt_builder)
    {        
        $this->jwt = $jwt_builder->jwt;
        $this->header = $jwt_builder->header;
        $this->claims = $jwt_builder->claims;

        if ($this->jwt != "") {
            $this->_decodeJWE($this->jwt);
        }

        return $this;
    }

    private function _encodeJWE()
    {       
        // base64 encode and build jwe from segments
        $this->jwt = implode(".", [
            Helper::json_b64_encode($this->header),
            Helper::base64url_encode($this->encrypted_key),
            Helper::base64url_encode($this->iv),
            Helper::base64url_encode($this->payload),
            Helper::base64url_encode($this->tag)
        ]);
    }

    private function _decodeJWE($jwt_string)
    {
        // break the jwe string to segments
        $segments = explode('.', $jwt_string);

        if(!$segments || count($segments)!=5){
            throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');
        }
        
        $this->header = Helper::json_b64_decode($segments[0]); // array
        $this->encrypted_key = Helper::base64url_decode($segments[1]); // encrypted key
        $this->iv = Helper::base64url_decode($segments[2]); // b64 plaintext initialization vector
        $this->payload = Helper::base64url_decode($segments[3]); // encrypted payload
        $this->tag = Helper::base64url_decode($segments[4]); // b64 tag

        $this->jwt = $jwt_string; // raw jwt
    }

    function encrypt($private_key_or_secret, $alg = 'RSA1_5', $enc = "A128CBC-HS256")
    {
        // Get algorithm class instance from string name $alg
        $KEY_ENCRYPTER = Algorithms::key_encrypting($alg);

        // Get algorithm class instance from string name $alg
        $CONTENT_ENCRYPTER = Algorithms::encrypting($enc);

        $this->header = [
            'typ' => 'JWT',
            'alg' => $KEY_ENCRYPTER::ALG,
            'enc' => $CONTENT_ENCRYPTER::ENC
        ] + $this->header; // Modify header befor encrypting - add typ and alg

        // generate random content encryption key
        $this->decrypted_key = openssl_random_pseudo_bytes($CONTENT_ENCRYPTER::KEYBITSLENGTH / 8);

        // generate random iv
        $this->iv = openssl_random_pseudo_bytes($CONTENT_ENCRYPTER::IVBITSLENGTH / 8);

        // Encrypt Key ;)
        $this->encrypted_key = $KEY_ENCRYPTER->encrypt($this->decrypted_key, $private_key_or_secret);

        // Encrypt claims ;)
        $this->payload = $CONTENT_ENCRYPTER->encrypt(Helper::json_b64_encode($this->claims), // b64 encoded claims
        $this->decrypted_key, // content encryption Key
        $this->iv, // initalization vector
        $this->tag // <- pointer !!!
        );

        if ($this->tag == null) { // if enctiption did not returend tag - calculate tag (not all encryption method will return tag)
            $this->tag = $CONTENT_ENCRYPTER->auth_tag(Helper::json_b64_encode($this->header), // b64 header
            Helper::base64url_encode($this->iv), // initalization vector
            Helper::base64url_encode($this->payload), // b64 payload a.k.a encrypted claims
            Helper::base64url_encode($this->decrypted_key) // content encryption Key
            );
        }

        $this->_encodeJWE();

        return $this;
    }

    function decrypt($public_key_or_secret, $alg = 'RSA1_5', $enc = "A128CBC-HS256")
    {

        // Get algorithm class instance from string name $alg
        $KEY_ENCRYPTER = Algorithms::key_encrypting($alg);

        // Get algorithm class instance from string name $alg
        $CONTENT_ENCRYPTER = Algorithms::encrypting($enc);

        // Decrypt Key ;)
        $this->decrypted_key = $KEY_ENCRYPTER->decrypt($this->encrypted_key, $public_key_or_secret);

        $tag = $this->tag;

        $decrypted_payload = $CONTENT_ENCRYPTER->decrypt($this->payload, // b64 encoded claims
        $this->decrypted_key, // content encryption Key
        $this->iv, // initalization vector
        $tag);
        if (! $decrypted_payload) {
            // failed decryption
            $this->claims = array();
            $this->decrypted = false;
            return $this;
        }

        $this->claims = Helper::json_b64_decode($decrypted_payload);

        if ($tag == null) {
            // if enctiption did not returend tag - calculate tag (not all encryption method will return tag)
            $tag = $CONTENT_ENCRYPTER->auth_tag(Helper::json_b64_encode($this->header), // b64 header
            Helper::base64url_encode($this->iv), // initalization vector
            Helper::base64url_encode($this->payload), // b64 payload
            Helper::base64url_encode($this->decrypted_key) // content encryption Key
            );
        }

        if ($tag == $this->tag) {
            $this->decrypted = true;
        }

        return $this;
    }
}