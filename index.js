const express = require('express')
const bodyParser = require('body-parser')
const { createJwks } = require('./jwks.js')
const { createSignatureHandlerFactory, validateSignatureHandlerFactory } = require('./handlers.js')


const app = express()
const port = 3000

app.use(express.urlencoded());
app.use(bodyParser.text({ type: 'application/json' }));

const jwks = createJwks();

app.get('/jwks', (req, res) => res.json(jwks));
app.get('/.well-known/openid-configuration', (req, res) => res.json({
    jwks_uri:  req.protocol+"://"+ req.headers.host + "/jwks"
}));

app.post('/create-signature', createSignatureHandlerFactory(jwks));
app.post('/validate-signature', validateSignatureHandlerFactory());

app.listen(port, () => console.log(`Example app listening on port ${port}!`));



