var cryptico = require('cryptico');


// The passphrase used to repeatably generate this RSA key. 
var PassPhrase = "Don't worry if it doesn't work right. If everything did, you'd be out of a job."; 
 
// The length of the RSA key, in bits. 
var Bits = 512; 	// length of the RSA key (512, 1024, 2048, 4096, 8192).

// Generate a public key
var RSAkey = cryptico.generateRSAKey(PassPhrase, Bits);
var PublicKeyString = cryptico.publicKeyString(RSAkey);  

/*
// Encrypting a message
var PlainText = "Matt, I need you to help me with my Starcraft strategy.";
var EncryptionResult = cryptico.encrypt(PlainText, PublicKeyString);
/* 	returns an object
	{ 
		status: 'success',
	  	cipher: 'fmqiQuvW1Rfj9/4uXouF0KzSyfomtvPwXr/nkKvNKXGypBD27bMKGl/uQUyCkQTAiWUaPYgDMtXJP9YsBg2uuS8EotPpN9twlro1F/jc4wuw1ZLKFSGNlzSERcG+nkXht4XNVqnfxck2iPRG9OCJI6ODZK8McRULfeVBS0kK2Kg=?aZkNY1t4jCH4mqDQ8HzMcFWwoUnqZ/hXD/mvXxUkRTpEavAKXTjOgujLpklYbEttkwUgc2gPgvby+RuCQ4Bry3XxUcyuuHgCY06Q3p9z4Vc=' 
	}
*/
/*
// Decrypting a message
var DecryptionResult = cryptico.decrypt(EncryptionResult.cipher, RSAkey);
/* 	returns an object
	{ 
		status: 'success',
		plaintext: 'Matt, I need you to help me with my Starcraft strategy.',
	  	signature: 'unsigned' 
	}
*/
module.exports.generateString = function(number) {
	var string = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for(var i = 0; i < number; i++) {
        string += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return string;
}

module.exports.encrypt = function(plainText) {
	return cryptico.encrypt(plainText, PublicKeyString);
}

module.exports.decrypt = function(cipher) {
	return cryptico.decrypt(cipher, RSAkey);
}