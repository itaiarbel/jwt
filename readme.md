
# PHP Jwt library by Itai Arbel

Easy to use lightweight user friendly jwt library
** no dependencies **  - all algorithms implemented using php openssl only.


Disclaimer:

22/08/2020 - **BETA** - all seems to be working ok,

NOT fully tested for security /
NOT fully RFC complience.
use at your own risk!


You are wellcome to use this library and help me improve it by finding bugs and implementing missing algorithms.

What it can do?
* JWS - HS256 - Sign / Verify 	-  with shared secret key
* JWS - HS384 - Sign / Verify 	-  with shared secret key
* JWS - HS512 - Sign / Verify 	-  with shared secret key
* JWS - RS256 - Sign / Verify	-  with private & private key
* JWS - RS384 - Sign / Verify 	-  with private & private key
* JWS - RS512 - Sign / Verify 	-  with private & private key
* JWE - RSA1_5 + A128CBC-HS256	-  Encrypt / Decrypt -  with private & private key
* JWE - RSA1_5 + A192CBC-HS384  -  Encrypt / Decrypt -  with private & private key
* JWE - RSA1_5 + A256CBC-HS512  -  Encrypt / Decrypt -  with private & private key
* JWE - RSA1_5 + A128GCM		-  Encrypt / Decrypt -  with private & private key
* JWE - RSA1_5 + A192GCM		-  Encrypt / Decrypt -  with private & private key
* JWE - RSA1_5 + A256GCM		-  Encrypt / Decrypt -  with private & private key


## Table of Contents
1. [Installetion](#installation)

2. [Builder](#builder)
3. [Builder Methods](#builder-methods)

4. [Checker](#checker)
5. [Checker Methods](#checker-methods)

6. [Algorithms](#algorithms)

7. [Contributions](#contributions)
8. [Contact](#contact)

## Installation

Run the following composer command:

```
composer require itaiarbel/jwt
```

Then use it in your project:

```
use Itaiarbel\Jwt\Jwt; 
```


## Builder

allows you to build jwt, then sign/encrypt them.

Example of use:

```
 $jws= Jwt::Builder()            
            ->jti() 
            ->claim('iss','me')
            ->claim('aud','you')
            ->exp(3600)  
            ->claim('sub','123123')                                                
            ->sign('SuPerSeCrEtKeY','HS256');

echo $jws->jwt; //your jws string

```

```
$private_rsa_key='
-----BEGIN PRIVATE KEY-----
...  generate your own 2048bit/4096bit RSA keys ...
-----END PRIVATE KEY-----';

$public_rsa_key='
-----BEGIN PUBLIC KEY-----
...  generate your own 2048bit/4096bit RSA keys ...
-----END PUBLIC KEY-----';


 $jws2= Jwt::Builder()
            ->header('kid','38890') //optional key id - for key menegment
			  ->jti()
            ->claim('iss','me')
            ->claim('aud','you')
            ->exp(3600)  
            ->nbf(600)         
            ->claim('sub','123123')                                    
            ->claim('user_verified','1')
            ->sign($private_rsa_key,'RS256'); 

echo $jws2->jwt; //your jws signed string using the private key

```

```

$private_rsa_key='
-----BEGIN PRIVATE KEY-----
...  generate your own 2048bit/4096bit RSA keys ...
-----END PRIVATE KEY-----';

$jwe= Jwt::Builder()
            ->header('kid','1') 
            ->jti() 
            ->claim('iss','me') 
            ->claim('aud','you')
            ->exp(3600)
            ->nbf(600)         
            ->claim('sub','123123')                                    
            ->claim('user_verified','1')
            ->encrypt($private_rsa_key,'RSA1_5','A128CBC-HS256');
                        
 echo $jwe->jwt; //your jwe string encrypted using the private key
 
```

##Builder Methods


claim(key, val) / claims([key=>val,key=>val...]) :  addes a claim/claims to the payload section of the token

```
->claim('first_name','john') //add claim
->claim('last_name','doe') // one by one
->claims([  				    //or add multiple claims as array
		   'first_name'=>'john',
		   'last_name'=>'doe'
		  ])

->claim('user',[  //adds json object claim under 'user'
			'user_id' => '123',
		   'first_name'=>'john',
		   'last_name'=>'doe'
		  ]);		  
```

header(key, val) :  addes a claim to the header section of the token 
(notice: header claims are not ecnrypted in JWE)

```
->header('kid','123') //set key id

```

exp(secs,server_ts[opt])  :  adds 'exp' token expiers time claim of time()+secs, you can set server timestamp if different timezone.

```
->exp(3600) //time()+3600
->exp(3600,$ts) // $ts + 3600
```

nfb(secs)  :  adds a 'nbf' token not valid before claim of time()+secs

```
->nbf(600) //time()+600
->nbf(600,$ts) //$ts+600
```

jti(val[opt])  :  adds a 'jti' token id claim of auto generated random GUID if no parameter provided

```
->jti() //e.g b1e029d4-c452-4ab4-9c0a-39db17896224
->jti('random-id-123-123') //or use your own id
->claim('jti','random-id-123-123') //you can use claim function instead
```

iss(val)/issuer(val)  :  adds a 'iss' token issuer claim

```
 ->iss('me') 
 ->issuer('me') //or
 ->claim('iss','me') //or 
```

sign(key, alg)  : finish the builder and sign the jwt. - > JWS

```
->sign('SuPerSeCrEtKeY','HS512'); //sign with HMAC-SHA512 using a secret key
->sign($private_key_pem,'RS512'); //sign with RSA-SHA512 using a private key
```

encrypt(key, alg, enc)  : finish the builder and encrypt the jwt. -> JWE

```
->encrypt($private_key_pem,'RSA1_5','A256CBC-HS512'); //encrypt using RSA & AES256CBC-HS512
->encrypt($private_key_pem,'RSA1_5','A256GCM'); //encrypt using RSA & AES128GCM
```



## Checker
Example of use:

JWS verify:

```     
    //this is a 5y valid token signed with HS256 with  key 'SuPerSeCrEtKeY'
    $jws_string="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyM2YxYmY5Ny02NTlkLTQ2MjAtOWY1Ni0yOGVjMWUxN2MyYmQiLCJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImlhdCI6MTU5ODExMjQ3NSwiZXhwIjoxNzU1NzkyNDc1LCJzdWIiOiIxMjMxMjMifQ.JSIWCGxG8ay-h3LKoZ9pCd5sx4cqK-Wqn2pKtJoBAn4";
    
    try{
        $jws= Jwt::Checker($jws_string)->verify('SuPerSeCrEtKeY','HS256');
    }catch(Exception $e){
        //exception will happen if the input is not valid jwt
        $jws=false;
        echo "INVALID TOKEN INPUT!<br>";         
    }
            
        if ($jws && $jws->validate()){  //validates exp & nbf & signiture here            
            echo "VALID TOKEN!!<br>";                       
            print_r($jws->getClaims()); //print all claims
            echo '<br><br>';
        }else{
            echo "TOKEN NOT VALID!!<br>";           
        }
        
        
        //same as above + checking extra fields like issuer        
        if ( 
            $jws &&                          //ckeck input of token
            $jws->verified && 			     // Signature verification
            $jws->checkExp() && 			  //If exp timstamp passed                       
            $jws->checkNbf() &&                 //checkNbf
            //up to here - same as calling:  $jws->validate()
            $jws->iss('me') && 			  //If issuer is"me"
            $jws->aud('you') 			  //If audience is "you"            
            ){
               echo "VALID TOKEN FROM ME TO YOU!!<br>";     
               print_r($jws->getClaims()); //print all claims
               echo '<br><br>';
           }else{
               echo "TOKEN NOT VALID!!<br>";
        }        

```

JWE decryption:

```

$public_rsa_key='
-----BEGIN PUBLIC KEY-----
...  generate your own 2048bit/4096bit RSA keys ...
-----END PUBLIC KEY-----';


     try{                   
            //start checker with jwt string input
            $jwe= Jwt::Checker($user_input_jwe);
 
            //you can get header claims before decrypting like: alg,enc,kid ect...
			  $header= $jwe->getHeaderClaims();
			  
		
            //$jwe->decrypt($public_key,$header['alg'],$header['enc']); //extract alg &enc from header           
            $jwe->decrypt($public_rsa_key,'RSA1_5','A128CBC-HS256');// or you can decrypt using known preset alg & enc
        
        }catch(Exception $e){ //error decrypting/parsing
            $jwe=false;            
        }
             
             
                         
        if ($jwe && $jwe->validate()){  //validates exp & nbf & decryption here            
            echo "VALID TOKEN!!<br>";                       
            print_r($jwe->getClaims()); //print all claims
            echo '<br><br>';
        }else{
            echo "TOKEN NOT VALID!!<br>";           
        }
        
        
        //same as above + checking extra fields like issuer        
        if ( 
            $jwe &&                          //ckeck input of token
            $jwe->decrypted && 			     // Signature verification
            $jwe->checkExp() && 			  //If exp timstamp passed                       
            $jwe->checkNbf() &&                 //checkNbf
            //up to here - same as calling:  $jws->validate()
            $jwe->iss('me') && 			  //If issuer is"me"
            $jwe->aud('you') 			  //If audience is "you"            
            ){
               echo "VALID TOKEN FROM ME TO YOU!!<br>";     
               print_r($jwe->getClaims()); //print all claims
               echo '<br><br>';
           }else{
               echo "TOKEN NOT VALID!!<br>";
        }   
            
```

Note: verified Not means Valid token, i'ts only checks signiture, not validity of the token time,
you must check the experation timestamp/nbf/iss blacklist/catch/database ect on your own... 



##Checker Methods

verify(key/secret,alg) - verify JWS using public key / secret

```
$jws->verify($public_key_pem,'RS512');
$jws->verify('secretkey','HS512');
```

decrypt(key/secret,alg,enc) - decrypting JWE using public key

```
$jwe->decrypt($public_key_pem,'RSA1_5','A256CBC-HS512');
```

getHeaderClaims():array - get array of all header claims in JWE/JWS

```
$jws->getHeaderClaims();
```

getHeaderClaim(name):string - get a specific claim from header

```
$jws->getHeaderClaim('kid');
```


hasHeaderClaim(name):bool - returns true/false if header claim exist

```
if($jws->hasHeaderClaim('kid')){
	$key= your_own_get_key_by_id(
		$jws->kid()
		);
	}
```

kid()/keyId():string    - get 'kid' calim from header

```
$kid= $jwe->kid();
$kid= $jwe->keyId();

```

alg()/algorithm():string  -  get 'alg' calim from header

```
$alg = $jws->alg();
$alg = $jws->algorithm();

```



enc()/encryption():string -  get 'enc' calim from header

```
$enc = $jwe->enc();
$enc = $jwe->encryption();

```

validate(server_ts[opt]):bool - validates signiture/decryption + exp + nbf

```
 if ($jwe && $jwe->validate()){
 	echo 'Token is valid and not expiered';
 }
```

checkExp(ts[opt]):bool - return true/false if exp claim time has passed

```
 if (!$jwe->checkExp()){
 	echo 'Token is expiered';
 }
```

checkNbf(ts[opt]):bool - return true/false if nbf time not before now.. 
note: if nbf claim not exist - returns true this this claim is optional

```
 if (!$jwe->checkNbf()){
 	echo 'Used Token too soon';
 }
```


checkClaim(name,expected_val):bool  - return true/false -  check claim agains expected value

```
 if ($jwe->checkClaim('user_verified','1')){
 	echo 'User is Verified!';
 }
```

checkHeaderClaim(name,expected_val):bool - return true/false -  check header claim agains expected value

```
 if ($jwe->checkHeaderClaim('kid','12')){
 	echo 'token is using key #12';
 }
```

getClaims():array - get array of all claims (will return empy array if token yet to be decrypted)

```
print_r($jws->getClaims());
```


getClaim(name):string - get specific claim by name  (will return empty string if token yet to be decrypted)

```
$username = $jws->getClaim('username');
```

hasClaim(name):bool - returns true/false if claim exist  (will return false if token yet to be decrypted)

```
if($jws->hasClaim('username')){
{ 
	echo 'hello '.$jws->getClaim('username');
}

```



iss()/issuer():string  - get isueer 'iss' claim

```
$jws->iss();
$jws->issuer();

```

sub()/subject():string - get subject 'sub' claim

```
$user_id = $jws->sub();
$user_id = $jws->subject();

```

aud()/audience():string - get audience 'aud' claim

```
$jws->aud();
$jws->audience();

```

exp()/expires():string - get expires time 'exp' claim

```
$jws->exp();
$jws->expires();

```

nbf()/notBefore():string  - get not before time 'nbf' claim

```
$jws->nbf();
$jws->notBefore();

```

iat()/issuedAt():string  - get issued time 'iat' claim
 
```
$jws->iat();
$jws->issuedAt();

```

jti()/id():string - - get token id 'jti' claim

```
$jws->jti();
$jws->id();

```



## Algorithms

Algorithms Implemented:
* HS256 -     HMAC-SHA256            - Sign / Verify
* HS384 -     HMAC-SHA384            - Sign / Verify
* HS512 -     HMAC-SHA512            - Sign / Verify
* RS256 - RSA-PKCS1-SHA256           - Sign / Verify
* RS384 - RSA-PKCS1-SHA384           - Sign / Verify
* RS512 - RSA-PKCS1-SHA512           - Sign / Verify
* RSA1_5 				             - Encrypt Key / Decrypt Key
* A128CBC_HS256 - AES-128-CBC SHA256 - Encrypt / Decrypt
* A192CBC_HS384 - AES-192-CBC SHA384 - Encrypt / Decrypt
* A256CBC_HS512 - AES-256-CBC SHA512 - Encrypt / Decrypt
* A128GCM       -     AES-128-GCM    - Encrypt / Decrypt 
* A192GCM       -     AES-192-GCM    - Encrypt / Decrypt
* A256GCM       -     AES-256-GCM    - Encrypt / Decrypt

Algorithms TODO: (maybe you can help?)
* dir
* PS256 
* PS384
* PS512
* ES256
* ES384
* ES512
* RSA-OAEP
* RSA-OAEP-256  
* A128KW
* A192KW
* A256KW        
* ECDH-ES
* ECDH-ES+A128KW
* ECDH-ES+A192KW
* ECDH-ES+A256KW
* A128GCMKW
* A192GCMKW
* A256GCMKW
* PBES2-HS256+A128KW
* PBES2-HS384+A192KW
* PBES2-HS512+A256KW

### Contributions
ways to contribute:
* add algorithms
* find bugs
* fix bugs
* improve existing code

### Support

* buy me a cup of coffee

### Contact
You can contact me at <itai@arbelis.com>