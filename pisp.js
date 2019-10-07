const { JWK, JWS } = require('jose')

const ISSUER = "some issuer";
const TRUSTED_ANCOR = "localhost:3000";

const createSignature = (alg, payload, key) => {

    const header = {
        alg: alg,
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

const X_PBX_ALG_HEADER = "x-pbx-alg";
const defaultAlgorithm = "PS256";

module.exports = {
    createConsentHandler : (jwks) => {
        jwks = jwks || {};
        let keys = jwks.keys || [];

        return (req, res) => {

            const alg = req.header(X_PBX_ALG_HEADER) || defaultAlgorithm;

            var signingKey = keys.find((_) => _.alg == alg);

            if(signingKey === undefined){
                throw "signingKey not found";
            }


            const jsonWebSignature = createSignature(alg, req.body, signingKey);
            const splitedSignature = jsonWebSignature.split(".");
            const signatureHeader = splitedSignature.shift();
            const signature = splitedSignature.pop();

            return res.send(`${signatureHeader}..${signature}`);

        }
    }
};