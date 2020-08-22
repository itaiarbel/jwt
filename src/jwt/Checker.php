<?php
namespace Itaiarbel\Jwt;

use Itaiarbel\Jwt\Helper;
use Itaiarbel\Jwt\Jws;
use Itaiarbel\Jwt\Jwe;

/**
 * JwtChecker - Checks and extracts information from a token
 *
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */
class JwtChecker extends Jwt
{

    var $jwt;

    // complete jwt encoded string
    var $header = array();

    // jwt header array
    var $claims = array();

    var $signature = "";

    // Signature verification status
    var $verified = false;

    // Signature verification status
    var $decrypted = false;

    // Algorithm
    var $alg = "";

    // Token id
    var $jti = "";

    function __construct($jwt_string = "")
    {
        if ($jwt_string != "") {
            $this->jwt = $jwt_string;

            // decode only the header (if you want alg/enc/kid from it before decrypting)
            $segments = explode('.', $this->jwt);
            if (! $segments) {
                throw new Exceptions\Exception_InvalidInput('Invalid JWT input.');
            }
            $this->header = Helper::json_b64_decode($segments[0]);
        }
    }

    public function verify($public_key_or_secret, $alg = 'HS256')
    {
        $jws = new Jws($this);
        $jws->verify($public_key_or_secret, $alg);
        $this->jwt = $jws->jwt;
        $this->header = $jws->header;
        $this->claims = $jws->claims;
        $this->signature = $jws->signature;
        $this->verified = $jws->verified;
        return $this;
    }

    public function decrypt($public_key_or_secret, $alg = 'RSA1_5', $enc = "A218CBC-HS256")
    {
        $jwe = new Jwe($this);
        $jwe->decrypt($public_key_or_secret, $alg, $enc);
        $this->jwt = $jwe->jwt;
        $this->header = $jwe->header;
        $this->claims = $jwe->claims;
        $this->decrypted = $jwe->decrypted;
        return $this;
    }

    function getClaims()
    {
        /**
         * Get all claims from the token
         *
         * @return Array() or key-value claims
         */
        return $this->claims;
    }

    function getHeaderClaims()
    {
        /**
         * Get all claims from the token header
         *
         * @return Array() or key-value claims
         */
        return $this->header;
    }

    function getClaim($claim_name)
    {
        /**
         * Returns a specifit claim by name
         *
         * @param String $claim_name
         *            the claim key name
         * @return Value string or an empty string if claim not exist
         */
        if (isset($this->claims[$claim_name])) {
            return $this->claims[$claim_name];
        } else {
            return "";
        }
    }

    function getHeaderClaim($claim_name)
    {
        /**
         * Returns a specifit header claim by name
         *
         * @param String $claim_name
         *            the claim key name
         * @return Value string or an empty string if claim not exist
         */
        if (isset($this->header[$claim_name])) {
            return $this->header[$claim_name];
        } else {
            return "";
        }
    }

    function hasClaim($claim_name)
    {
        /**
         * Checks if a specifit claim exist
         *
         * @param String $claim_name
         *            the claim key name
         * @return Bool True/False
         */
        if (isset($this->claims[$claim_name])) {
            return true;
        } else {
            return false;
        }
    }

    function hasHeaderClaim($claim_name)
    {
        /**
         * Checks if a specifit header claim exist
         *
         * @param String $claim_name
         *            the claim key name
         * @return Bool True/False
         */
        if (isset($this->header[$claim_name])) {
            return true;
        } else {
            return false;
        }
    }

    function checkClaim($claim_name, $expected_value)
    {
        /**
         * Checks if if claim matches expected value
         *
         * @param String $claim_name
         *            the claim key name
         * @param String $expected_value
         *            the value to match
         * @return Bool True/False
         */
        if (isset($this->claims[$claim_name]) == true) {
            if ($this->claims[$claim_name] == $expected_value) {
                return true;
            }
        }
        return false;
    }

    function checkHeaderClaim($claim_name, $expected_value)
    {
        /**
         * Checks if if header claim matches expected value
         *
         * @param String $claim_name
         *            the claim key name
         * @param String $expected_value
         *            the value to match
         * @return Bool True/False
         */
        if (isset($this->header[$claim_name]) == true) {
            if ($this->header[$claim_name] == $expected_value) {
                return true;
            }
        }
        return false;
    }

    function checkExp($now = 0)
    {
        /**
         * Checks token is expiered
         *
         * @param Timestamp $now
         *            timestamp to match, default is current time
         * @return Bool True/False
         */
        if ($now == 0) {
            $now = time();
        }
        if (isset($this->claims['exp']) == true) {
            if ($now < $this->claims['exp']) {
                return true;
            }
        }
        return false;
    }

    function checkNbf($now = 0)
    {
        /**
         * Checks token is nbf ts valid
         *
         * @param Timestamp $now
         *            timestamp to match, default is current time
         * @return Bool True/False
         */
        if ($now == 0) {
            $now = time();
        }
        if (isset($this->claims['nbf']) && isset($this->claims['exp'])) {
            if ($this->claims['nbf'] < $now && $this->claims['exp'] > $now) {
                return true;
            }
            return false; // nbf check failed
        }
        // nbf is optional, so check only if exists or else pass
        // so you can check nbf on valid tokens without nbf claim without them failing.
        return true;
    }

    function validate($now = 0)
    {
        /**
         * Checks token if is valid and not expiered
         *
         * @param Timestamp $now
         *            timestamp to match, default is current time
         * @return Bool True/False
         */
        if ($now == 0) {
            $now = time();
        }
        if( ($this->verified || $this->decrypted) && $this->checkExp($now) && $this->checkNbf($now)){
            return true;
        }
        return false;        
    }
    
    
    function jti()
    {
        /**
         * Get token id (jti)
         *
         * @return String value
         */
        return $this->getClaim('jti');
    }

    function id()
    {
        /**
         * Get token id (jti)
         *
         * @return String value
         */
        return $this->getClaim('jti');
    }

    
    function iat()
    {
        /**
         * Get token id (jti)
         *
         * @return String value
         */
        return $this->getClaim('iat');
    }
    
    function issuedAt()
    {
        /**
         * Get token id (jti)
         *
         * @return String value
         */
        return $this->getClaim('iat');
    }
    
    
    function exp()
    {
        /**
         * Get token id (jti)
         *
         * @return String value
         */
        return $this->getClaim('exp');
    }
    
    function expires()
    {
        /**
         * Get token id (jti)
         *
         * @return String value
         */
        return $this->getClaim('exp');
    }
    
    
    
    function nbf()
    {
        /**
         * Get token not before (nbf)
         *
         * @return String value
         */
        return $this->getClaim('nbf');
    }

    function notBefore()
    {
        /**
         * Get token not before (nbf)
         *
         * @return String value
         */
        return $this->getClaim('nbf');
    }

    function aud()
    {
        /**
         * Get token audience (aud)
         *
         * @return String value
         */
        return $this->getClaim('aud');
    }

    function audience()
    {
        /**
         * Get token audience (aud)
         *
         * @return String value
         */
        return $this->getClaim('aud');
    }

    function iss()
    {
        /**
         * Get token issuer (iss)
         *
         * @return String value
         */
        return $this->getClaim('iss');
    }

    function issuer()
    {
        /**
         * Get token issuer (iss)
         *
         * @return String value
         */
        return $this->getClaim('iss');
    }

    function sub()
    {
        /**
         * Get token subject (sub)
         *
         * @return String value
         */
        return $this->getClaim('sub');
    }

    function subject()
    {
        /**
         * Get token subject (sub)
         *
         * @return String value
         */
        return $this->getClaim('sub');
    }

    function kid()
    {
        /**
         * Get token key id from header (kid)
         *
         * @return String value
         */
        return $this->getHeaderClaim('kid');
    }

    function keyId()
    {
        /**
         * Get token key id from header (kid)
         *
         * @return String value
         */
        return $this->getHeaderClaim('kid');
    }

    function alg()
    {
        /**
         * Get token algorithm from header (alg)
         *
         * @return String value
         */
        return $this->getHeaderClaim('alg');
    }

    function algorithm()
    {
        /**
         * Get token algorithm from header (alg)
         *
         * @return String value
         */
        return $this->getHeaderClaim('alg');
    }
    
    
    function enc()
    {
        /**
         * Get token algorithm from header (alg)
         *
         * @return String value
         */
        return $this->getHeaderClaim('enc');
    }
    
    function encription()
    {
        /**
         * Get token algorithm from header (alg)
         *
         * @return String value
         */
        return $this->getHeaderClaim('enc');
    }
}