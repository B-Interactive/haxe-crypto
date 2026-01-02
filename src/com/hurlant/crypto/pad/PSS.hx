package com.hurlant.crypto.pad;

import com.hurlant.util.Std2;
import haxe.Int32;
import com.hurlant.crypto.hash.SHA1;
import com.hurlant.crypto.prng.SecureRandom;
import com.hurlant.math.BigInteger;
import com.hurlant.util.ByteArray;
import com.hurlant.crypto.tls.TLSError;

class PSS {
    private var hash:com.hurlant.crypto.hash.IHash;
    private var saltLength:Int;

    public function new(hash:com.hurlant.crypto.hash.IHash = null, saltLength:Int = -1) {
        this.hash = (hash != null) ? hash : new SHA1();
        this.saltLength = (saltLength >= 0) ? saltLength : this.hash.getHashSize(); // Default to hash size
    }

    // RSA-compatible padding for signing: ByteArray -> Int32 -> Int32 -> Int32 -> ByteArray
    public function pad(src:ByteArray, end:Int32, n:Int32, type:Int32 = 0x01):ByteArray {
        var mLen = Std.int(Std2.min3(end - src.position, src.length - src.position, n - saltLength - hash.getHashSize() - 2));
        if (mLen < 0)
            throw new TLSError("PSS::pad: Message too long", TLSError.decode_error);

        var m = new ByteArray();
        src.readBytes(m, 0, mLen);
        src.position += mLen;

        var mHash = hash.hash(m);
        var salt = SecureRandom.getSecureRandomBytes(saltLength);

        var mPrime = new ByteArray();
        mPrime.writeBytes(mHash);
        mPrime.writeBytes(salt);

        var h = hash.hash(mPrime);
        var ps = new ByteArray();
        for (i in 0...(n - saltLength - hash.getHashSize() - 2))
            ps.writeByte(0);

        var db = new ByteArray();
        db.writeBytes(ps);
        db.writeByte(1);
        db.writeBytes(salt);

        var dbMask = mgf1(h, n - hash.getHashSize() - 1);
        db = xorByteArrays(db, dbMask);

        var em = new ByteArray();
        em.writeBytes(db);
        em.writeBytes(h);
        em.writeByte(0xBC); // Trailer

        return em;
    }

    // RSA-compatible unpadding for verification: BigInteger -> Int32 -> Int32 -> ByteArray
    // Note: For proper PSS, the original message must be provided for verification.
    // RSAKey needs to be updated to pass the original message (e.g., modify verify to pass src).
    public function unpad(src:BigInteger, n:Int32, type:Int32 = 0x01, originalMessage:ByteArray = null):ByteArray {
        if (originalMessage == null) {
            throw new TLSError("PSS::unpad: Original message required for verification", TLSError.decode_error);
        }

        var em = src.toByteArray();
        if (em.length != n || em.get(em.length - 1) != 0xBC)
            return null; // Invalid signature

        var h = em.sub(em.length - hash.getHashSize() - 1, hash.getHashSize());
        var db = em.sub(0, em.length - hash.getHashSize() - 1);

        var dbMask = mgf1(h, n - hash.getHashSize() - 1);
        db = xorByteArrays(db, dbMask);

        // Verify padding
        var i = 0;
        while (i < db.length - saltLength - 1 && db.get(i) == 0)
            i++;
        if (db.get(i) != 1)
            return null; // Invalid padding

        var salt = db.sub(i + 1, saltLength);

        // Recompute mHash from original message
        var mHash = hash.hash(originalMessage);

        var mPrime = new ByteArray();
        mPrime.writeBytes(mHash);
        mPrime.writeBytes(salt);

        var hPrime = hash.hash(mPrime);
        if (!byteArrayEquals(h, hPrime))
            return null; // Hash mismatch

        return originalMessage; // Verification successful, return original message
    }

    private function mgf1(seed:ByteArray, len:Int):ByteArray {
        var t = new ByteArray();
        var counter = 0;
        while (t.length < len) {
            var c = new ByteArray();
            c.writeBytes(seed);
            c.writeUnsignedInt(counter);
            var h = hash.hash(c);
            t.writeBytes(h);
            counter++;
        }
        return t.sub(0, len);
    }

    private function xorByteArrays(a:ByteArray, b:ByteArray):ByteArray {
        var result = new ByteArray();
        for (i in 0...Std.int(Math.min(a.length, b.length))) {
            result.writeByte(a.get(i) ^ b.get(i));
        }
        return result;
    }

    private function byteArrayEquals(a:ByteArray, b:ByteArray):Bool {
        if (a.length != b.length)
            return false;
        for (i in 0...a.length)
            if (a.get(i) != b.get(i))
                return false;
        return true;
    }
}