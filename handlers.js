const { JWK, JWS, JWKS } = require('jose');
const request = require("request");

const ISSUER = "some issuer";
const TRUSTED_ANCOR = "localhost:3000";
const X_PBX_ALG_HEADER = "x-pbx-alg";
const X_JWS_SIGNATURE = "x-jws-signature";

const PS256 = "PS256";
const RS256 = "RS256";
const ES256 = "ES256";

const signedRequestHeader = {
    // alg: alg,
    typ: "JOSE",
    cty: "json",
    // kid: key.kid,
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


const createSignature = (alg, payload, key, header) => {

    header = header || {};

    header["alg"] = alg;
    header["kid"] = key.kid;

    let sign = new JWS.Sign(payload);
    sign.recipient(JWK.asKey(key), header);

    return sign.sign("compact");

}

const validateHeader = (header) => {
    if (!header) {
        console.log("header is not present");
        return false;
    }

    const buff = new Buffer(header, 'base64');
    const headerAsJson = JSON.parse(buff.toString('ascii'));

    if (!headerAsJson.alg) {
        console.log("header.alg is not present");
        return false;
    }

    if (headerAsJson.alg !== PS256 && headerAsJson.alg !== RS256 && headerAsJson.alg !== ES256) {
        console.log("header.alg is not valid");
        return false;
    }

    if (headerAsJson.typ && headerAsJson.typ !== "JOSE") {
        console.log("header.typ is not valid");
        return false;
    }

    if (headerAsJson.cty && headerAsJson.cty !== "json" && headerAsJson.cty !== "application/json") {
        console.log("header.cty is not valid");
        return false;
    }

    if (!headerAsJson.kid) {
        console.log("header.kid is not present");
        return false;
    }

    if (headerAsJson.b64 && headerAsJson.b64 !== false) {
        console.log("header.b64 is not valid");
        return false;
    }

    if (!headerAsJson["http://openbanking.org.uk/iat"]) {
        console.log("header.\"http://openbanking.org.uk/iat\" is not present");
        return false;
    }

    if (!headerAsJson["http://openbanking.org.uk/iss"]) {
        console.log("header.\"http://openbanking.org.uk/iss\" is not present");
        return false;
    }

    if (!headerAsJson["http://openbanking.org.uk/tan"]) {
        console.log("header.\"http://openbanking.org.uk/tan\" is not present");
        return false;
    }

    const acceptedValue = [
        "b64", ISSUED_AT_CLAIM, ISSUER_CLAIM, TRUSTED_ANCHOR_CLAIM
    ];

    if(!headerAsJson.crit){
        console.log("header.crit is not present");
        return false;
    }

    if(headerAsJson.crit.sort().join(",") !== acceptedValue.sort().join(",")){
        console.log("header.crit is not valid");
        return false;
    }

    return true;
}

const validateSignature = (header, payload, signature, onSuccess, onError) => {
    const buff = new Buffer(header, 'base64');
    const headerAsJson = JSON.parse(buff.toString('ascii'));

    const trustedAnchorParts = headerAsJson[TRUSTED_ANCHOR_CLAIM].split(":").join(" ").split("/").join(" ").split(" ");

    let wellKnownUrl;
    if(trustedAnchorParts[0] === "localhost"){
        wellKnownUrl = "http://";
    } else {
        wellKnownUrl = "https://";
    }

    wellKnownUrl += headerAsJson[TRUSTED_ANCHOR_CLAIM];
    wellKnownUrl += "/.well-known/openid-configuration"

    request.get(
        wellKnownUrl,
         (error, response, body) => {
            if (!error && response.statusCode == 200) {
                var bodyAsJson = JSON.parse(body);

                

                request.get(
                    bodyAsJson["jwks_uri"],
                     (error, response, body) => {
                        if (!error && response.statusCode == 200) {
                            let verificationResult;
                            try{
                                const keyStore = JWKS.asKeyStore(JSON.parse(body));

                                let buff = new Buffer(payload);
                                let base64data = buff.toString('base64');
                                

                                verificationResult = JWS.verify(`${header}.${base64data}.${signature}`, keyStore, {
                                    crit : ["b64", ISSUED_AT_CLAIM, ISSUER_CLAIM, TRUSTED_ANCHOR_CLAIM]
                                });
                            }
                            catch(e){
                                return onError(e);
                            }

                            onSuccess(verificationResult);
                        }else{
                            onError(error);
                        }
            
                    }
                );

            }else{
                onError(error);
            }

        }
    );
}

module.exports = {
    createSignatureHandlerFactory: (jwks) => {
        jwks = jwks || {};
        let keys = jwks.keys || [];

        return (req, res) => {

            const alg = req.header(X_PBX_ALG_HEADER) || PS256;

            var signingKey = keys.find((_) => _.alg == alg);

            if (!signingKey) {
                throw "signingKey not found";
            }


            const jsonWebSignature = createSignature(alg, req.body, signingKey, signedRequestHeader);
            const splitedSignature = jsonWebSignature.split(".");
            const signatureHeader = splitedSignature.shift();
            const signature = splitedSignature.pop();

            return res.send(`${signatureHeader}..${signature}`);

        };
    },
    validateSignatureHandlerFactory: () => {
        return (req, res) => {

            const signature = req.header(X_JWS_SIGNATURE);

            if (!signature) {
                return res.status(400).send("Signature is not present");
            }

            const signatureParts = signature.split("..");

            if (signatureParts.length !== 2) {
                return res.status(400).send("Invalid signature form");
            }

            if (!validateHeader(signatureParts[0])) {
                return res.status(400).send("Invalid signature header");
            }

            validateSignature(signatureParts[0], req.body, signatureParts[1], 
                (body) => res.send(body),
                (error) => res.status(400).send("Invalid signature"));


        };
    },
    createDynamicClientRegistrationRequestHandlerFactory: (jwks) => {
        jwks = jwks || {};
        let keys = jwks.keys || [];

        return (req, res) => {

            const alg = req.header(X_PBX_ALG_HEADER) || PS256;

            var signingKey = keys.find((_) => _.alg == alg);

            if (!signingKey) {
                throw "signingKey not found";
            }


            const jsonWebSignature = createSignature(alg, req.body, signingKey);
            return res.send(jsonWebSignature);

        };
    }
};