package com.hurlant.tests.crypto.curve;

import haxe.io.Bytes;
import com.hurlant.crypto.cert.curve.Curve25519;
import com.hurlant.util.Hex;

class DebugTest {
    public static function main() {
        // Test 1: Simple key exchange with fixed keys
        trace("=== Test 1: Simple Key Exchange ===");
        var alicePriv = Bytes.alloc(32);
        for (i in 0...32) alicePriv.set(i, 8 + i);
        
        var bobPriv = Bytes.alloc(32);
        for (i in 0...32) bobPriv.set(i, 16 + i);
        
        var alicePub = Curve25519.genKeypair(alicePriv);
        var bobPub = Curve25519.genKeypair(bobPriv);
        
        trace("Alice private: " + Hex.fromBytes(alicePriv));
        trace("Alice public:  " + Hex.fromBytes(alicePub));
        trace("Bob private:   " + Hex.fromBytes(bobPriv));
        trace("Bob public:    " + Hex.fromBytes(bobPub));
        
        var aliceShared = Curve25519.combineKeys(alicePriv, bobPub);
        var bobShared = Curve25519.combineKeys(bobPriv, alicePub);
        
        trace("Alice computed shared: " + Hex.fromBytes(aliceShared));
        trace("Bob computed shared:   " + Hex.fromBytes(bobShared));
        trace("Shared secrets equal? " + bytesEqual(aliceShared, bobShared));
        
        // Test 2: RFC 7748 vector - check byte order
        trace("\n=== Test 2: RFC 7748 Vector (checking byte order) ===");
        var privHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        var expectedPubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        
        var priv = Hex.toBytes(privHex);
        var expectedPub = Hex.toBytes(expectedPubHex);
        
        trace("Input private (as parsed):    " + Hex.fromBytes(priv));
        trace("Expected public (as parsed):  " + Hex.fromBytes(expectedPub));
        
        var pub = Curve25519.genKeypair(priv);
        trace("Generated public:             " + Hex.fromBytes(pub));
        
        trace("Match? " + bytesEqual(pub, expectedPub));
        
        // Try reversing the expected output
        var expectedReversed = Bytes.alloc(32);
        for (i in 0...32) expectedReversed.set(i, expectedPub.get(31 - i));
        trace("Expected public (reversed):   " + Hex.fromBytes(expectedReversed));
        trace("Match reversed? " + bytesEqual(pub, expectedReversed));
        
        // Check individual byte differences
        trace("\nByte-by-byte comparison:");
        for (i in 0...32) {
            if (pub.get(i) != expectedPub.get(i)) {
                trace('  Byte $i: got ${pub.get(i)}, expected ${expectedPub.get(i)}');
            }
        }
    }
    
    private static function bytesEqual(a:Bytes, b:Bytes):Bool {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (i in 0...a.length) {
            if (a.get(i) != b.get(i)) return false;
        }
        return true;
    }
}