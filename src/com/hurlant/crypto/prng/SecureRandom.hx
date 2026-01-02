package com.hurlant.crypto.prng;

import haxe.io.BytesData;
import haxe.io.Bytes;

class SecureRandom {
    // @TODO: IMPORTANT!!
    /**
     * Gather anything we have that isn't entirely predictable:
     *  - memory used
     *  - system capabilities
     *  - timing stuff
     *  - installed fonts
     */
    static public function getSecureRandomBytes(length:Int):Bytes {
        var reason = '';
        try {
            #if flash
                return Bytes.ofData(untyped __global__["flash.crypto.generateRandomBytes"](length));
            #elseif js
                js.Syntax.code('var Crypto = typeof crypto === "undefined" ? require("crypto") : crypto');
                var bytes:Dynamic = js.Syntax.code("(Crypto.randomBytes) ? Crypto.randomBytes({0}) : Crypto.getRandomValues(new Uint8Array({0}))", length);
                var out = Bytes.alloc(length);
                for (n in 0 ... length) out.set(n, bytes[n]);
                return out;
            #elseif python
                var out = Bytes.alloc(length);
                var bytes = RandomOs.urandom(length);
                for (n in 0 ... length) out.set(n, bytes[n]);
                return out;
            #elseif java
                var rng = new java.security.SecureRandom();
                var result = Bytes.alloc(length);
                rng.nextBytes(cast result.getData());
                return result;
            #elseif cs
                var out = Bytes.alloc(length);
                var rng = new cs.system.security.cryptography.RNGCryptoServiceProvider();
                rng.GetBytes(out.getData());
                return out;
            #elseif sys
            var out = Bytes.alloc(length);
            #if windows
                /**
                 * For windows target, uses PowerShell to call .NET Crypto API.
                 * This has numerous security and performance concerns.
                 * @TODO: Consider creating extern that calls BCryptGenRandom.
                 */                 
                var proc = new sys.io.Process("powershell", [
                    "-NoProfile",
                    "-Command",
                    "$r=[System.Security.Cryptography.RNGCryptoServiceProvider]::new();" + 
                    "$b=New-Object byte[] " + length + ";$r.GetBytes($b);$r.Dispose();$b-join','"
                ]);
                var output = StringTools.trim(proc.stdout.readAll().toString());
                var code = proc.exitCode();
                proc.close();
                
                // Validate process exit code
                if (code != 0) {
                    throw "PowerShell process failed with exit code: " + code;
                }
                
                // Parse output and validate length
                if (output.length == 0) {
                    throw "PowerShell returned empty output";
                }
                
                var parts = output.split(",");
                if (parts.length != length) {
                    throw "PowerShell returned " + parts.length + " bytes, expected " + length;
                }
                
                // Parse each byte value
                for (i in 0...length) {
                    var val = Std.parseInt(parts[i]);
                    if (val == null || val < 0 || val > 255) {
                        throw "Invalid byte value at index " + i + ": " + parts[i];
                    }
                    out.set(i, val);
                }
            #else
                var input = sys.io.File.read("/dev/urandom");
                input.readBytes(out, 0, length);
                input.close();                
            #end
            return out;
        #end
        } catch (e:Dynamic) {
            reason = '$e';
        }
        throw "Can't find a secure source of random bytes. Reason: " + reason;
    }

    //static private function getDefaultSeeds():Array<Int> {
    //}
}

#if python
@:pythonImport("os")
extern class RandomOs {
    static public function urandom(count:Int):Array<Int>;
}
#end
