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

    base64Url(bytes) {
        let binary = "";
        bytes.forEach((byte) => binary += String.fromCharCode(byte));
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
};
