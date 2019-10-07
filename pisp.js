const { JWK, JWS } = require('jose')

const ISSUER = "some issuer";
const TRUSTED_ANCOR = "localhost:3000";

const createSignature = (payload, key) => {

    const header = {
        alg: "PS256",
        typ: "JOSE",
        cty: "json",
        kid: key.kid,
        b64: false,
        "http://openbanking.org.uk/iat": new Date().getTime(),
        "http://openbanking.org.uk/iss": ISSUER,
        "http://openbanking.org.uk/tan": TRUSTED_ANCOR,
        crit: [
            "b64",
            "http://openbanking.org.uk/iat",
            "http://openbanking.org.uk/iss",
            "http://openbanking.org.uk/tan",
        ]
    };

    
    let sign = new JWS.Sign(payload);
    sign.recipient(JWK.asKey(key), header);

    return sign.sign("compact");

}

module.exports = {
    createConsentHandler : (jwks) => {
        jwks = jwks || {};
        let keys = jwks.keys || [];

        var signingKey = keys.find((_) => _.alg == "PS256");

        return (req, res) => {

            const jsonWebSignature = createSignature(req.body, signingKey);
            const splitedSignature = jsonWebSignature.split(".");
            const signatureHeader = splitedSignature.shift();
            const signature = splitedSignature.pop();

            return res.send(`${signatureHeader}..${signature}`);

        }
    }
};