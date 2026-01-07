package com.hurlant.tests.crypto.curve;

import haxe.io.Bytes;
import com.hurlant.crypto.cert.curve.Curve25519;
import com.hurlant.tests.BaseTestCase;
import com.hurlant.util.Hex;

class Curve25519Test extends BaseTestCase {

    // --------------------------------------------------
    // Helpers (local, deterministic, minimal)
    // --------------------------------------------------

    private function bytesEqual(a:Bytes, b:Bytes):Bool {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (i in 0...a.length) {
            if (a.get(i) != b.get(i)) return false;
        }
        return true;
    }

    private function randomPrivateKey():Bytes {
        var b = Bytes.alloc(32);
        for (i in 0...32) {
            b.set(i, Std.random(256));
        }
        return b;
    }

    private function pad32(b:Bytes):Bytes {
        if (b.length == 32) return b;
        var out = Bytes.alloc(32);
        out.blit(32 - b.length, b, 0, b.length);
        return out;
    }

    // --------------------------------------------------
    // Tests
    // --------------------------------------------------

    /**
     * Temporary simple test
     */
    public function test_simple_output():Void {
        var priv = Bytes.alloc(32);
        for (i in 0...32) priv.set(i, i);  // 0,1,2,3...31
        
        var pub = Curve25519.genKeypair(priv);
        
        trace("Generated public key:");
        for (i in 0...32) {
            trace("  byte[" + i + "] = " + pub.get(i));
        }
    }

    /**
     * Temporary debug test.
     */
    public function test_public_key_changes():Void {
        var priv1 = Bytes.alloc(32);
        priv1.set(0, 8);   // 8 & 248 = 8

        var priv2 = Bytes.alloc(32);
        priv2.set(0, 16);  // 16 & 248 = 16

        var pub1 = Curve25519.genKeypair(priv1);
        var pub2 = Curve25519.genKeypair(priv2);

        trace("pub1 hex: " + Hex.fromBytes(pub1));
        trace("pub2 hex: " + Hex.fromBytes(pub2));

        assertEquals(false, bytesEqual(pub1, pub2));
    }


    /**
     * genKeypair() must always return a 32-byte public key
     */
    public function test_public_key_length():Void {
        var priv = randomPrivateKey();
        var pub  = Curve25519.genKeypair(priv);

        assertEquals(32, pub.length);
    }

    /**
     * Same private key must always generate the same public key
     */
    public function test_deterministic_public_key():Void {
        var priv = randomPrivateKey();

        var pub1 = Curve25519.genKeypair(priv);
        var pub2 = Curve25519.genKeypair(priv);

        assertEquals(true, bytesEqual(pub1, pub2));
    }

    /**
     * Different private keys must (with overwhelming probability)
     * produce different public keys
     */
    public function test_distinct_private_keys():Void {
        var priv1 = randomPrivateKey();
        var priv2 = randomPrivateKey();

        var pub1 = Curve25519.genKeypair(priv1);
        var pub2 = Curve25519.genKeypair(priv2);

        assertEquals(false, bytesEqual(pub1, pub2));
    }

    /**
     * X25519 key agreement must be symmetric:
     *   a(bG) == b(aG)
     */
    public function test_key_exchange_symmetry():Void {
        var alicePriv = randomPrivateKey();
        var bobPriv   = randomPrivateKey();

        var alicePub = Curve25519.genKeypair(alicePriv);
        var bobPub   = Curve25519.genKeypair(bobPriv);

        var aliceShared = Curve25519.combineKeys(alicePriv, bobPub);
        var bobShared   = Curve25519.combineKeys(bobPriv, alicePub);

        assertEquals(true, bytesEqual(aliceShared, bobShared));
    }

    /**
     * RFC 7748 test vector: known private key → known public key
     */
    public function test_rfc7748_vector():Void {
        var privHex =
            "77076d0a7318a57d3c16c17251b26645" +
            "df4c2f87ebc0992ab177fba51db92c2a";

        var pubHex =
            "8520f0098930a754748b7ddcb43ef75a" +
            "0dbf3a0d26381af4eba4a98eaa9b4e6a";

        var priv = pad32(Hex.toBytes(privHex));
        var expectedPub = pad32(Hex.toBytes(pubHex));

        var pub = Curve25519.genKeypair(priv);

        assertEquals(true, bytesEqual(pub, expectedPub));
    }

    /**
     * Zero private keys are valid per RFC 7748 (after clamping)
     */
    public function test_zero_private_key():Void {
        var zeroPriv = Bytes.alloc(32);
        var pub = Curve25519.genKeypair(zeroPriv);

        assertEquals(32, pub.length);
    }

    /**
     * Private keys must be exactly 32 bytes
     */
    public function test_invalid_key_lengths():Void {
        var shortKey = Bytes.alloc(16);
        var longKey  = Bytes.alloc(64);

        var shortThrew = false;
        var longThrew  = false;

        try {
            Curve25519.genKeypair(shortKey);
        } catch (e:Dynamic) {
            shortThrew = true;
        }

        try {
            Curve25519.genKeypair(longKey);
        } catch (e:Dynamic) {
            longThrew = true;
        }

        assertEquals(true, shortThrew);
        assertEquals(true, longThrew);
    }
}
