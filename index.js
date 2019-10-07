const express = require('express')
const bodyParser = require('body-parser')
const { createJwks } = require('./jwks.js')
const { createConsentHandler } = require('./pisp.js')


const app = express()
const port = 3000

app.use(express.urlencoded());
app.use(bodyParser.text({ type: 'application/json' }));

const jwks = createJwks();

app.get('/jwks', (req, res) => res.json(jwks))
app.post('/pisp', createConsentHandler(jwks))

app.get('/.well-known/openid-configuration', (req, res) => res.json({
    jwks_uri:  req.protocol+"://"+ req.headers.host + "/jwks"
}))


app.listen(port, () => console.log(`Example app listening on port ${port}!`))



