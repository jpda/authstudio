window.authstudioCrypto = {
    async signJwt(privateKeyJwkJson, signingInput, algorithm) {
        const jwk = JSON.parse(privateKeyJwkJson);

        if (algorithm === "ES256") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["sign"]
            );
            const data = new TextEncoder().encode(signingInput);
            const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data);
            return authstudioCrypto.base64Url(new Uint8Array(signature));
        }

        if (algorithm === "RS256") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                false,
                ["sign"]
            );
            const data = new TextEncoder().encode(signingInput);
            const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, data);
            return authstudioCrypto.base64Url(new Uint8Array(signature));
        }

        throw new Error(`Unsupported algorithm: ${algorithm}`);
    },

    async verifyJwt(jwt, publicKeyJwkJson, algorithm) {
        const parts = jwt.split(".");
        if (parts.length !== 3) {
            throw new Error("Signed JWT must have three segments.");
        }

        const jwk = JSON.parse(publicKeyJwkJson);
        const signingInput = `${parts[0]}.${parts[1]}`;
        const signature = authstudioCrypto.base64UrlDecodeBytes(parts[2]);
        const data = new TextEncoder().encode(signingInput);

        if (algorithm === "ES256") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["verify"]
            );
            return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
        }

        if (algorithm === "ES384") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "ECDSA", namedCurve: "P-384" },
                false,
                ["verify"]
            );
            return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, signature, data);
        }

        if (algorithm === "ES512") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "ECDSA", namedCurve: "P-521" },
                false,
                ["verify"]
            );
            return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-512" }, key, signature, data);
        }

        if (algorithm === "RS256") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                false,
                ["verify"]
            );
            return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
        }

        if (algorithm === "RS384") {
            const key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
                false,
                ["verify"]
            );
            return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
        }

        throw new Error(`Unsupported verification algorithm: ${algorithm}`);
    },

    async decryptJwe(jweCompact, privateKeyJwkJson) {
        const parts = jweCompact.split(".");
        if (parts.length !== 5) {
            throw new Error("JWE must have five dot-separated segments.");
        }

        const [protectedHeader, encryptedKey, iv, ciphertext, tag] = parts;
        const header = JSON.parse(authstudioCrypto.base64UrlDecodeString(protectedHeader));
        const jwk = JSON.parse(privateKeyJwkJson);
        const aad = new TextEncoder().encode(protectedHeader);

        const cek = await authstudioCrypto.unwrapContentEncryptionKey(
            header,
            encryptedKey,
            jwk
        );

        let plaintext = await authstudioCrypto.decryptCiphertext(
            header.enc,
            cek,
            iv,
            ciphertext,
            tag,
            aad
        );

        if (header.zip === "DEF") {
            plaintext = await authstudioCrypto.inflateDeflate(plaintext);
        }

        return new TextDecoder().decode(plaintext);
    },

    async unwrapContentEncryptionKey(header, encryptedKey, jwk) {
        const alg = header.alg;
        const enc = header.enc;
        const cekBits = authstudioCrypto.encBitLength(enc);

        if (alg === "dir") {
            return authstudioCrypto.directKey(jwk, cekBits);
        }

        if (alg === "RSA-OAEP" || alg === "RSA-OAEP-256") {
            return authstudioCrypto.rsaDecryptCek(alg, encryptedKey, jwk);
        }

        if (alg === "A128KW" || alg === "A192KW" || alg === "A256KW") {
            const kek = await authstudioCrypto.importSymmetricKey(jwk, authstudioCrypto.kwBitLength(alg));
            return authstudioCrypto.aesKeyUnwrap(kek, encryptedKey, cekBits);
        }

        if (alg.startsWith("ECDH-ES")) {
            const derived = await authstudioCrypto.ecdhDeriveKey(header, jwk, alg, enc, cekBits);
            if (alg === "ECDH-ES") {
                return derived;
            }

            const kekBits = authstudioCrypto.kwBitLength(alg.split("+")[1]);
            const kek = await crypto.subtle.importKey("raw", derived, { name: "AES-KW", length: kekBits }, false, ["unwrapKey"]);
            return authstudioCrypto.aesKeyUnwrap(kek, encryptedKey, cekBits);
        }

        throw new Error(`Unsupported JWE key management algorithm: ${alg}`);
    },

    async rsaDecryptCek(alg, encryptedKey, jwk) {
        const hash = alg === "RSA-OAEP-256" ? "SHA-256" : "SHA-1";
        const key = await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "RSA-OAEP", hash },
            false,
            ["decrypt"]
        );
        const wrapped = authstudioCrypto.base64UrlDecodeBytes(encryptedKey);
        return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, wrapped));
    },

    directKey(jwk, cekBits) {
        if (jwk.kty !== "oct") {
            throw new Error("dir requires a symmetric oct JWK.");
        }

        const key = authstudioCrypto.base64UrlDecodeBytes(jwk.k);
        if (key.length * 8 !== cekBits) {
            throw new Error(`Expected a ${cekBits}-bit oct key for ${cekBits / 8}-byte content encryption.`);
        }

        return key;
    },

    async importSymmetricKey(jwk, bits) {
        if (jwk.kty !== "oct") {
            throw new Error("Symmetric key wrap requires an oct JWK.");
        }

        const raw = authstudioCrypto.base64UrlDecodeBytes(jwk.k);
        if (raw.length * 8 !== bits) {
            throw new Error(`Expected a ${bits}-bit oct key.`);
        }

        return crypto.subtle.importKey("raw", raw, { name: "AES-KW", length: bits }, false, ["unwrapKey"]);
    },

    async aesKeyUnwrap(kek, encryptedKey, cekBits) {
        const wrapped = authstudioCrypto.base64UrlDecodeBytes(encryptedKey);
        const cek = await crypto.subtle.unwrapKey(
            "raw",
            wrapped,
            kek,
            "AES-KW",
            { name: "AES-GCM", length: cekBits },
            true,
            ["decrypt"]
        );
        return new Uint8Array(await crypto.subtle.exportKey("raw", cek));
    },

    async ecdhDeriveKey(header, jwk, alg, enc, cekBits) {
        if (!header.epk) {
            throw new Error("ECDH JWE header is missing epk (ephemeral public key).");
        }

        const privateKey = await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDH", namedCurve: jwk.crv || "P-256" },
            false,
            ["deriveBits"]
        );

        const publicKey = await crypto.subtle.importKey(
            "jwk",
            header.epk,
            { name: "ECDH", namedCurve: header.epk.crv || "P-256" },
            false,
            []
        );

        const curve = header.epk.crv || jwk.crv || "P-256";
        const curveBits = { "P-256": 256, "P-384": 384, "P-521": 521 }[curve] || 256;

        const sharedSecret = new Uint8Array(
            await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, curveBits)
        );

        const algorithmId = alg === "ECDH-ES"
            ? enc
            : alg;

        const otherInfo = authstudioCrypto.concat(
            authstudioCrypto.utf8LengthPrefixed(algorithmId),
            authstudioCrypto.prefixed(authstudioCrypto.decodeOptionalB64Url(header.apu)),
            authstudioCrypto.prefixed(authstudioCrypto.decodeOptionalB64Url(header.apv)),
            authstudioCrypto.suppPubInfo(alg === "ECDH-ES" ? cekBits : authstudioCrypto.kwBitLength(alg.split("+")[1]))
        );

        const derivedBits = alg === "ECDH-ES" ? cekBits : authstudioCrypto.kwBitLength(alg.split("+")[1]);
        return authstudioCrypto.concatKdf(sharedSecret, derivedBits, otherInfo);
    },

    async concatKdf(sharedSecret, keyDataLenBits, otherInfo) {
        const hashLen = 32;
        const reps = Math.ceil(keyDataLenBits / (hashLen * 8));
        let output = new Uint8Array(0);

        for (let i = 1; i <= reps; i++) {
            const counter = new Uint8Array(4);
            new DataView(counter.buffer).setUint32(0, i, false);
            const digest = new Uint8Array(
                await crypto.subtle.digest("SHA-256", authstudioCrypto.concat(counter, sharedSecret, otherInfo))
            );
            output = authstudioCrypto.concat(output, digest);
        }

        return output.slice(0, keyDataLenBits / 8);
    },

    async decryptCiphertext(enc, cek, iv, ciphertext, tag, aad) {
        if (enc.endsWith("GCM")) {
            const key = await crypto.subtle.importKey(
                "raw",
                cek,
                { name: "AES-GCM", length: cek.length * 8 },
                false,
                ["decrypt"]
            );

            const ct = authstudioCrypto.base64UrlDecodeBytes(ciphertext);
            const tagBytes = authstudioCrypto.base64UrlDecodeBytes(tag);
            const combined = authstudioCrypto.concat(ct, tagBytes);

            return new Uint8Array(
                await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: authstudioCrypto.base64UrlDecodeBytes(iv),
                        additionalData: aad,
                        tagLength: tagBytes.length * 8
                    },
                    key,
                    combined
                )
            );
        }

        throw new Error(`Unsupported JWE content encryption: ${enc}`);
    },

    async inflateDeflate(bytes) {
        if (typeof DecompressionStream === "undefined") {
            throw new Error("DEF decompression is not supported in this browser.");
        }

        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
        const buffer = await new Response(stream).arrayBuffer();
        return new Uint8Array(buffer);
    },

    encBitLength(enc) {
        if (enc.startsWith("A128")) return 128;
        if (enc.startsWith("A192")) return 192;
        if (enc.startsWith("A256")) return 256;
        throw new Error(`Unsupported enc value: ${enc}`);
    },

    kwBitLength(alg) {
        if (alg === "A128KW") return 128;
        if (alg === "A192KW") return 192;
        if (alg === "A256KW") return 256;
        throw new Error(`Unsupported key wrap algorithm: ${alg}`);
    },

    utf8LengthPrefixed(value) {
        const bytes = new TextEncoder().encode(value);
        const len = new Uint8Array(4);
        new DataView(len.buffer).setUint32(0, bytes.length, false);
        return authstudioCrypto.concat(len, bytes);
    },

    prefixed(bytes) {
        const len = new Uint8Array(4);
        new DataView(len.buffer).setUint32(0, bytes.length, false);
        return authstudioCrypto.concat(len, bytes);
    },

    suppPubInfo(bits) {
        const buf = new Uint8Array(4);
        new DataView(buf.buffer).setUint32(0, bits, false);
        return buf;
    },

    decodeOptionalB64Url(value) {
        if (!value) {
            return new Uint8Array(0);
        }

        return authstudioCrypto.base64UrlDecodeBytes(value);
    },

    concat(...arrays) {
        const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const output = new Uint8Array(total);
        let offset = 0;
        for (const arr of arrays) {
            output.set(arr, offset);
            offset += arr.length;
        }
        return output;
    },

    base64Url(bytes) {
        let binary = "";
        bytes.forEach((byte) => binary += String.fromCharCode(byte));
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },

    base64UrlDecodeString(str) {
        const padded = str.replace(/-/g, "+").replace(/_/g, "/");
        const pad = padded.length % 4;
        const paddedStr = pad ? padded + "====".slice(pad) : padded;
        return atob(paddedStr);
    },

    base64UrlDecodeBytes(str) {
        const binary = authstudioCrypto.base64UrlDecodeString(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
};
