/*
	An attempt at implementing the Playfair cipher in Javascript.
	
	Uses the omit-q pattern, rather than i/j pattern, for simplicity.
	
	Copyright (c) Jack Newcombe 2012
	
	License: Apache License Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0.html
*/

(function(){

var alpha = "abcdefghijklmnoprstuvwxyz";

// Private Utils

var digramify = function(plaintext) {
	var digrams = [], i, pt = plaintext.toLowerCase();
	//Validate
	for(i = 0; i < plaintext.length; i++){
		if(pt[i+1]){
			if(pt[i] === pt[i+1]){
				pt = pt.replace(pt[i]+pt[i+1], pt[i] + "x" + pt[i+1]);
			}
		}
	}
	// Digramify
	for(i = 0; i < plaintext.length; i += 2) {
		digrams.push([plaintext[i], plaintext[i+1] || "z"]);
	}
	return digrams;
};


// Public Class
var PlayfairTable = function(privateKey) {
	// Validate
	if(!privateKey || privateKey.length < 5 || privateKey.length > 25) {
		throw "ERROR: Bad private key '" + privateKey + "'.";
	}
	// Prepare table
	var pk = privateKey.toLowerCase() + alpha;
	var hash = [[],[],[],[],[]], poshash = {}; // memoize table and char positions.
	var pki = { x: 0, y: 0 }, i, usedhash = [];
	// Add private key to table
	for(i = 0; pki.x < 5 && pki.y < 5; i++) {
		if(usedhash.indexOf(pk[i]) !== -1) { continue; } else { usedhash.push(pk[i]); }
		console.log(JSON.stringify(pki) + " = " + pk[i]);
		hash[pki.y][pki.x] = pk[i];
		poshash[pk[i]] = { x: pki.x, y: pki.y };
		pki = ( pki.x === 4 ? { x: 0, y: pki.y + 1 } : { x: pki.x + 1, y: pki.y } );
	}
	
	var crypt = function(intext, isEncrypt) {
		var digrams = digramify(intext.toLowerCase()), i, ciphertext = "", ie = isEncrypt;
		for(i = 0; i < digrams.length; i++) {
			var d1p = poshash[digrams[i][0]], d2p = poshash[digrams[i][1]];
			// Rectangle
			if(d1p.x !== d2p.x && d1p.y !== d2p.y) {
				ciphertext += hash[d1p.y][d2p.x];
				ciphertext += hash[d2p.y][d1p.x];
			} else
			// Column
			if(d1p.y !== d2p.y && d1p.x === d2p.x) {
				ciphertext += hash[(d1p.y === (ie ? 4 : 0) ? (ie ? 0 : 4) : d1p.y + (ie ? 1 : -1) )][d1p.x];
				ciphertext += hash[(d2p.y === (ie ? 4 : 0) ? (ie ? 0 : 4) : d2p.y + (ie ? 1 : -1) )][d2p.x];
			} else
			// Row
			if(d1p.x !== d2p.x && d1p.y === d2p.y) {
				ciphertext += hash[d1p.y][(d1p.x === (ie ? 4 : 0) ? (ie ? 0 : 4) : d1p.x + (ie ? 1 : -1) )];
				ciphertext += hash[d2p.y][(d2p.x === (ie ? 4 : 0) ? (ie ? 0 : 4) : d2p.x + (ie ? 1 : -1) )];
			}
		}
		return ciphertext;
	};
	
	// Public interface
	this.decrypt = function(ciphertext) { return crypt(ciphertext, false); };
	this.encrypt = function(plaintext)  { return crypt(plaintext,   true); };
	// Some public utils
	this.setKey = function(newpk) { pk = newpk.toLowerCase() + alpha; };
	this.getKey = function()      { return hash;                      };
};

// Test
var table = new PlayfairTable("testkey");
console.log(JSON.stringify(table.getKey(), true));
var plaintext = "testplaintext";
var ciphertext = table.encrypt(plaintext);
console.log("plaintext to ciphertext: " + ciphertext);
var decodetext = table.decrypt(ciphertext);
console.log("ciphertext to plaintext: " + decodetext);

}());