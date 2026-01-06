/**
 * AS3CryptoTests
 *
 * @author	Tim Kurvers <tim@moonsphere.net>
 */
package com.hurlant.tests;


import com.hurlant.tests.crypto.extra.UUIDTest;
import com.hurlant.tests.crypto.extra.ROT13Test;
import com.hurlant.tests.crypto.rsa.RSAKeyTest;
import com.hurlant.tests.crypto.curve.Curve25519Test;
import com.hurlant.tests.math.BigIntegerTest;
import com.hurlant.tests.crypto.CryptoTest;
import haxe.unit.TestRunner;
import com.hurlant.tests.crypto.hash.*;
import com.hurlant.tests.crypto.prng.*;
import com.hurlant.tests.crypto.symmetric.*;
import com.hurlant.tests.util.*;

/**
 * haxe-crypto unit tests runner
 */
class HaxeCryptoTests {
    static function main() {
        //var a = new BigInteger("112374128763487126349871263984761238", 10);
        //trace(a.toString(10));
        //return;
        //assert(a.toString(10), "112374128763487126349871263984761238");

        var tr = new TestRunner();
        tr.add(new RandomTest());
        tr.add(new Std2Test());
        tr.add(new MD2Test());
        tr.add(new MD5Test());
        tr.add(new RMD160Test());
        tr.add(new ARC4Test());
        tr.add(new HexTest());
        tr.add(new Base64Test());
        tr.add(new ArrayUtilTest());
        tr.add(new XTeaKeyTest());
        tr.add(new SHA1Test());
        tr.add(new SHA256Test());
        tr.add(new SHA224Test());
        tr.add(new HMACTest());
        tr.add(new TLSPRFTest());
        tr.add(new BlowFishKeyTest());
        tr.add(new DESKeyTest());
        tr.add(new TripleDESKeyTest());
        tr.add(new AESKeyTest());
        tr.add(new CFB8ModeTest());
        tr.add(new CBCModeTest());
        tr.add(new CFBModeTest());
        tr.add(new CTRModeTest());
        tr.add(new OFBModeTest());
        tr.add(new ECBModeTest());
        tr.add(new CryptoTest());
        tr.add(new BigIntegerTest());
        tr.add(new RSAKeyTest());
        tr.add(new Curve25519Test());
        tr.add(new ROT13Test());
        tr.add(new UUIDTest());
        //tr.add(new TLSTest());

        tr.run();
    }
}
