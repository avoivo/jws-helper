const jose = require('jose');
const express = require('express')
const app = express()
const port = 3000

const {
  JWE,   // JSON Web Encryption (JWE) 
  JWK,   // JSON Web Key (JWK)
  JWKS,  // JSON Web Key Set (JWKS)
  JWS,   // JSON Web Signature (JWS)
  JWT,   // JSON Web Token (JWT)
  errors // errors utilized by jose
} = jose;

const key1 = JWK.generateSync("RSA");
const key2 = JWK.generateSync("RSA");
const signingKey = JWK.generateSync('RSA', 2048, { use: 'sig', alg: 'PS256' })

const keystore = new jose.JWKS.KeyStore(key1, key2, signingKey);

// console.log(JSON.stringify(keystore.toJWKS(true), null, 4));

app.get('/jwks', (req, res) => res.json(keystore.toJWKS(true)))

app.listen(port, () => console.log(`Example app listening on port ${port}!`))



