const express = require('express')
const app = express()
const port = 3000

const { CreateJwks } = require('./jwks.js')

const jwks = CreateJwks();

app.get('/jwks', (req, res) => res.json(jwks))

app.listen(port, () => console.log(`Example app listening on port ${port}!`))



