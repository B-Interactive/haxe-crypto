package com.hurlant.crypto.cert.curve;

import haxe.io.Bytes;
import haxe.Int64;

/**
 * Curve25519 / X25519 Diffie-Hellman implementation.
 * 
 * Direct port of TweetNaCl to Haxe.
 */
class Curve25519 {
	private static inline function gf():Array<Int64> {
		return [for (_ in 0...16) Int64.ofInt(0)];
	}

	private static function set25519(r:Array<Int64>, a:Array<Int64>):Void {
		for (i in 0...16)
			r[i] = a[i];
	}

	private static function car25519(o:Array<Int64>):Void {
		var c:Int64;
		for (i in 0...16) {
			o[i] = Int64.add(o[i], Int64.shl(Int64.ofInt(1), 16));
			c = Int64.shr(o[i], 16);
			var target_index = (i + 1) * (i < 15 ? 1 : 0);
			var add_amount = Int64.sub(c, Int64.ofInt(1));
			add_amount = Int64.add(add_amount, Int64.mul(Int64.ofInt(37), Int64.mul(Int64.sub(c, Int64.ofInt(1)), Int64.ofInt(i == 15 ? 1 : 0))));
			o[target_index] = Int64.add(o[target_index], add_amount);
			o[i] = Int64.sub(o[i], Int64.shl(c, 16));
		}
	}

	private static function sel25519(p:Array<Int64>, q:Array<Int64>, b:Int):Void {
		var t:Int64;
		var c = Int64.ofInt(~(b - 1));
		for (i in 0...16) {
			t = Int64.and(c, Int64.xor(p[i], q[i]));
			p[i] = Int64.xor(p[i], t);
			q[i] = Int64.xor(q[i], t);
		}
	}

	private static function pack25519(o:Bytes, n:Array<Int64>):Void {
		var b:Int64;
		var m = gf(), t = gf();
		for (i in 0...16)
			t[i] = n[i];
		car25519(t);
		car25519(t);
		car25519(t);
		for (j in 0...2) {
			m[0] = Int64.sub(t[0], Int64.ofInt(0xffed));
			for (i in 1...15) {
				m[i] = Int64.sub(Int64.sub(t[i], Int64.ofInt(0xffff)), Int64.ushr(m[i - 1], 16));
				m[i - 1] = Int64.and(m[i - 1], Int64.ofInt(0xffff));
			}
			m[15] = Int64.sub(Int64.sub(t[15], Int64.ofInt(0x7fff)), Int64.ushr(m[14], 16));
			b = Int64.ushr(m[15], 16);
			m[14] = Int64.and(m[14], Int64.ofInt(0xffff));
			sel25519(t, m, 1 - Int64.toInt(Int64.and(b, Int64.ofInt(1))));
		}
		for (i in 0...16) {
			var val = Int64.toInt(Int64.and(t[i], Int64.ofInt(0xFFFF)));
			o.set(2 * i, val & 0xff);
			o.set(2 * i + 1, (val >> 8) & 0xff);
		}
	}

	private static function unpack25519(o:Array<Int64>, n:Bytes):Void {
		for (i in 0...16)
			o[i] = Int64.ofInt(n.get(2 * i) + (n.get(2 * i + 1) << 8));
		o[15] = Int64.and(o[15], Int64.ofInt(0x7fff));
	}

	private static function A(o:Array<Int64>, a:Array<Int64>, b:Array<Int64>):Void {
		for (i in 0...16)
			o[i] = Int64.add(a[i], b[i]);
	}

	private static function Z(o:Array<Int64>, a:Array<Int64>, b:Array<Int64>):Void {
		for (i in 0...16)
			o[i] = Int64.sub(a[i], b[i]);
	}

	private static function M(o:Array<Int64>, a:Array<Int64>, b:Array<Int64>):Void {
		var t = [for (_ in 0...31) Int64.ofInt(0)];
		for (i in 0...16)
			for (j in 0...16)
				t[i + j] = Int64.add(t[i + j], Int64.mul(a[i], b[j]));
		for (i in 0...15)
			t[i] = Int64.add(t[i], Int64.mul(Int64.ofInt(38), t[i + 16]));
		for (i in 0...16)
			o[i] = t[i];
		car25519(o);
		car25519(o);
	}

	private static function S(o:Array<Int64>, a:Array<Int64>):Void {
		M(o, a, a);
	}

	private static function inv25519(o:Array<Int64>, i:Array<Int64>):Void {
		var c = gf();
		for (a in 0...16)
			c[a] = i[a];
		for (a in 0...253) {
			S(c, c);
			if (a != 2 && a != 4)
				M(c, c, i);
		}
		for (a in 0...16)
			o[a] = c[a];
	}

	private static function crypto_scalarmult(q:Bytes, n:Bytes, p:Bytes):Void {
		var z = Bytes.alloc(32);
		var x = gf();
		var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
		var _121665 = gf();
		_121665[0] = Int64.ofInt(0xDB41);
		_121665[1] = Int64.ofInt(1);
		
		for (i in 0...31)
			z.set(i, n.get(i));
		z.set(31, (n.get(31) & 127) | 64);
		z.set(0, z.get(0) & 248);
		unpack25519(x, p);
		
		for (i in 0...16) {
			b[i] = x[i];
			d[i] = Int64.ofInt(0);
			a[i] = Int64.ofInt(0);
			c[i] = Int64.ofInt(0);
		}
		a[0] = Int64.ofInt(1);
		d[0] = Int64.ofInt(1);
		
		for (i in 0...255) {
			var bit_index = 254 - i;
			var r = Int64.toInt(Int64.ushr(Int64.ofInt(z.get(bit_index >>> 3)), bit_index & 7)) & 1;
			sel25519(a, b, r);
			sel25519(c, d, r);
			A(e, a, c);
			Z(a, a, c);
			A(c, b, d);
			Z(b, b, d);
			S(d, e);
			S(f, a);
			M(a, c, a);
			M(c, b, e);
			A(e, a, c);
			Z(a, a, c);
			S(b, a);
			Z(c, d, f);
			M(a, c, _121665);
			A(a, a, d);
			M(c, c, a);
			M(a, d, f);
			M(d, b, x);
			S(b, e);
			sel25519(a, b, r);
			sel25519(c, d, r);
		}
		
		inv25519(c, c);
		M(a, a, c);
		pack25519(q, a);
	}

	public static function genKeypair(privateKey:Bytes):Bytes {
		if (privateKey.length != 32)
			throw "Private key must be 32 bytes";

		var basepoint = Bytes.alloc(32);
		basepoint.set(0, 9);

		var publicKey = Bytes.alloc(32);
		crypto_scalarmult(publicKey, privateKey, basepoint);
		return publicKey;
	}

	public static function combineKeys(privateKey:Bytes, publicKey:Bytes):Bytes {
		if (privateKey.length != 32 || publicKey.length != 32)
			throw "Keys must be 32 bytes";

		var sharedSecret = Bytes.alloc(32);
		crypto_scalarmult(sharedSecret, privateKey, publicKey);
		return sharedSecret;
	}
}