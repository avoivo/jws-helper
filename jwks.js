const {
    JWE,   // JSON Web Encryption (JWE) 
    JWK,   // JSON Web Key (JWK)
    JWKS,  // JSON Web Key Set (JWKS)
    JWS,   // JSON Web Signature (JWS)
    JWT,   // JSON Web Token (JWT)
    errors // errors utilized by jose
} =  require('jose');

const key1 = JWK.generateSync("RSA");
const key2 = JWK.generateSync("RSA");
const signingKey = JWK.generateSync('RSA', 2048, { use: 'sig', alg: 'PS256' })

const keystore = new JWKS.KeyStore(key1, key2, signingKey);

module.exports = {
    CreateJwks : () => keystore.toJWKS(true)
};