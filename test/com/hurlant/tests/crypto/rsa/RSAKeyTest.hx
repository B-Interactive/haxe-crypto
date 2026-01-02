/**
 * RSAKeyTest
 *
 * A test class for RSAKey
 * Copyright (c) 2007 Henri Torgemane
 *
 * See LICENSE.txt for full license information.
 */
package com.hurlant.tests.crypto.rsa;

import com.hurlant.crypto.pad.PKCS1;
import com.hurlant.tests.*;
import com.hurlant.crypto.rsa.RSAKey;
import com.hurlant.util.Hex;
import com.hurlant.util.der.PEM;
import com.hurlant.util.ByteArray;

class RSAKeyTest extends BaseTestCase {
    public function test_smoke() {
        var N = (
            "C4E3F7212602E1E396C0B6623CF11D26204ACE3E7D26685E037AD2507DCE82FC" +
            "28F2D5F8A67FC3AFAB89A6D818D1F4C28CFA548418BD9F8E7426789A67E73E41"
        );
        var E = "10001";
        var D = (
            "7cd1745aec69096129b1f42da52ac9eae0afebbe0bc2ec89253598dcf454960e" +
            "3e5e4ec9f8c87202b986601dd167253ee3fb3fa047e14f1dfd5ccd37e931b29d"
        );
        var P = "f0e4dd1eac5622bd3932860fc749bbc48662edabdf3d2826059acc0251ac0d3b";
        var Q = "d13cb38fbcd06ee9bca330b4000b3dae5dae12b27e5173e4d888c325cda61ab3";
        var DMP1 = "b3d5571197fc31b0eb6b4153b425e24c033b054d22b9c8282254fe69d8c8c593";
        var DMQ1 = "968ffe89e50d7b72585a79b65cfdb9c1da0963cceb56c3759e57334de5a0ac3f";
        var IQMP = "d9bc4f420e93adad9f007d0e5744c2fe051c9ed9d3c9b65f439a18e13d6e3908";
        
        trace("Creating RSA key with 512-bit key size");
        var rsa = RSAKey.parsePrivateKey(N, E, D, P, Q, DMP1, DMQ1, IQMP);
        
        // Test with a short message that fits within OAEP limits
        var txt = "hello";  // Fits OAEP limit (~22 bytes for 512-bit key)
        trace("Testing with message: " + txt);
        var src = Hex.toArray(Hex.fromString(txt));
        trace("Source byte length: " + src.length);
        
        var dst = new ByteArray();
        var dst2 = new ByteArray();
        
        trace("Encrypting...");
        rsa.encrypt(src, dst, src.length);  // OAEP default
        trace("Encrypted byte length: " + dst.length);
        
        trace("Decrypting...");
        rsa.decrypt(dst, dst2, dst.length);  // OAEP default
        trace("Decrypted byte length: " + dst2.length);
        
        var txt2 = Hex.toString(Hex.fromArray(dst2));
        trace("Original: " + txt);
        trace("Decrypted: " + txt2);
        assert(txt, txt2);
    }

    public function test_generate() {
        trace("Generating 512-bit RSA key");
        var rsa = RSAKey.generate(512, "10001");  // Use 512 bits for OAEP compatibility
        var txt = "hello";
        trace("Testing with message: " + txt);
        var src = Hex.toArray(Hex.fromString(txt));
        trace("Source byte length: " + src.length);
        
        var dst = new ByteArray();
        var dst2 = new ByteArray();
        
        trace("Encrypting...");
        rsa.encrypt(src, dst, src.length);  // OAEP default
        trace("Encrypted byte length: " + dst.length);
        
        trace("Decrypting...");
        rsa.decrypt(dst, dst2, dst.length);  // OAEP default
        trace("Decrypted byte length: " + dst2.length);
        
        var txt2 = Hex.toString(Hex.fromArray(dst2));
        trace("Original: " + txt);
        trace("Decrypted: " + txt2);
        assert(txt, txt2);
    }

    public function test_pem() {
        var pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MGQCAQACEQDJG3bkuB9Ie7jOldQTVdzPAgMBAAECEQCOGqcPhP8t8mX8cb4cQEaR\n" +
            "AgkA5WTYuAGmH0cCCQDgbrto0i7qOQIINYr5btGrtccCCQCYy4qX4JDEMQIJAJll\n" +
            "OnLVtCWk\n" +
            "-----END RSA PRIVATE KEY-----"
        );
        trace("Reading PEM key");
        var rsa = PEM.readRSAPrivateKey(pem);
        
        var txt = "hi";  // Shorten to fit PKCS1
        trace("Testing with message: " + txt);
        var src = Hex.toArray(Hex.fromString(txt));
        trace("Source byte length: " + src.length);
        
        var dst = new ByteArray();
        var dst2 = new ByteArray();
        
        trace("Encrypting...");
        // Create PKCS1 instance and use it for padding
        var pkcs1 = new PKCS1();
        rsa.encrypt(src, dst, src.length, pkcs1.pad);  // Use PKCS1 for small key
        trace("Encrypted byte length: " + dst.length);
        
        trace("Decrypting...");
        rsa.decrypt(dst, dst2, dst.length, pkcs1.unpad);  // Use PKCS1 for small key
        trace("Decrypted byte length: " + dst2.length);
        
        var txt2 = Hex.toString(Hex.fromArray(dst2));
        trace("Original: " + txt);
        trace("Decrypted: " + txt2);
        assert(txt, txt2);
    }

    public function test_longText() {
        trace("Testing long text with PKCS1");
        var pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MGQCAQACEQDJG3bkuB9Ie7jOldQTVdzPAgMBAAECEQCOGqcPhP8t8mX8cb4cQEaR\n" +
            "AgkA5WTYuAGmH0cCCQDgbrto0i7qOQIINYr5btGrtccCCQCYy4qX4JDEMQIJAJll\n" +
            "OnLVtCWk\n" +
            "-----END RSA PRIVATE KEY-----"
        );
        var rsa = PEM.readRSAPrivateKey(pem);

        var txt = "PKCS1 test";  // Can be longer with PKCS1
        trace("Testing with message: " + txt);
        var src = Hex.toArray(Hex.fromString(txt));
        trace("Source byte length: " + src.length);
        
        var dst = new ByteArray();
        var dst2 = new ByteArray();
        
        trace("Encrypting...");
        // Create PKCS1 instance and use it for padding
        var pkcs1 = new PKCS1();
        rsa.encrypt(src, dst, src.length, pkcs1.pad);  // Use PKCS1 for small key
        trace("Encrypted byte length: " + dst.length);
        
        trace("Decrypting...");
        rsa.decrypt(dst, dst2, dst.length, pkcs1.unpad);  // Use PKCS1 for small key
        trace("Decrypted byte length: " + dst2.length);
        
        var txt2 = Hex.toString(Hex.fromArray(dst2));
        trace("Original: " + txt);
        trace("Decrypted: " + txt2);
        assert(txt, txt2);
    }
}