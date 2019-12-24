import express from 'express'
import querystring from 'querystring'
import { Photon } from '@prisma/photon'

import configurePassport from './auth/configurePassport'

const router = express.Router()
const photon = new Photon()
const passport = configurePassport()

router.get('/register', (req, res) => {
  res.render('register', {})
})

router.post('/register', async (req, res) => {
  try {
    await photon.connect()

    const client = await photon.clients.create({
      data: {
        ...req.body,
        client_id: 'asd787238hs78asa87281728aSasaSasaS',
        client_secret: 'nkdjDAsdanwe123sdas141098d'
      }
    })

    res.status(200).send(client)
  } catch (error) {
    console.log(error)
    res.status(500).send(error)
  } finally {
    await photon.disconnect()
  }
})

router.get('/login', (req, res) => {
  const query = querystring.stringify(req.query)
  res.render('login', { query })
})

router.post('/login', passport.authenticate('local'), (req, res) => {
  const url = new URL(req.headers.referer)

  res.redirect(`/authorize${url.search}`)
})

router.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/login')
})

router.get('/signup', (req, res) => {
  res.render('signup')
})

router.post('/signup', async (req, res) => {
  try {
    await photon.connect()

    const user = await photon.users.create({
      data: req.body
    })

    res.status(200).send(user)
  } catch (error) {
    console.log(error)
    res.status(500).send(error)
  } finally {
    await photon.disconnect()
  }
})

router.get('/authorize', async (req, res, next) => {
  try {
    if (!req.query.client_id) {
      return res.send('Missing required parameter client_id')
    }

    if (!req.query.redirect_uri) {
      return res.send('Missing required parameter redirect_uri')
    }

    if (!req.query.response_type) {
      return res.send('response_type must be code or token')
    }

    await photon.connect()

    const client = await photon.clients.findOne({
      where: { client_id: req.query.client_id },
      select: {
        client_id: true,
        redirect_uri: true
      }
    })

    if (!client) {
      return res.send('Invalid client')
    }

    if (
      req.query.redirect_uri &&
      req.query.redirect_uri !== client.redirect_uri
    ) {
      return res.send('Invalid redirect_uri')
    }

    if (!req.user) {
      const query = querystring.stringify(req.query)
      const url = `/login?${query}`

      res.redirect(url)
    }

    res.render('authorize', { user: req.user, client: client })
  } catch (error) {
    await photon.disconnect()

    res.send(error.message)
  }
})

router.post('/authorize/:action', (req, res) => {
  const actions = ['accept', 'reject']
  const url = new URL(req.headers.referer)
  const search = url.search.replace('?', '')
  const params = querystring.parse(search)
  const action = req.params.action

  if (!action || !actions.includes(action) || action !== 'accept') {
    const query = {
      error: 'access_denied',
      error_description: 'Invalid action or request denied',
      state: params.state
    }

    if (!params.state) {
      delete query.state
    }

    return res.redirect(
      `${params.redirect_uri}?${querystring.stringify(query)}`
    )
  }

  const query = {
    code: 'du7q22easSASFsmmsmaSALKN9',
    state: params.state
  }

  if (!params.state) {
    delete query.state
  }

  res.redirect(`${params.redirect_uri}?${querystring.stringify(query)}`)
})

router.post('/token', async (req, res) => {})

router.get('/userinfo', (req, res) => {})

router.get('/docs', (req, res) => {})

router.get('/.well-known/oauth-authorization-server', (req, res) => {
  const meta = {
    issuer: 'http://localhost:5000',
    authorization_endpoint: 'http://localhost:5000/authorize',
    token_endpoint: 'http://localhost:5000/token',
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'private_key_jwt'
    ],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256'],
    userinfo_endpoint: 'http://localhost:5000/userinfo',
    jwks_uri: 'http://localhost:5000/jwks.json',
    registration_endpoint: 'http://localhost:5000/register',
    scopes_supported: [
      'openid',
      'profile',
      'email',
      'address',
      'phone',
      'offline_access'
    ],
    response_types_supported: ['code', 'token'],
    service_documentation: 'http://localhost:5000/docs',
    ui_locales_supported: ['en-US']
  }

  res.status(200).send(meta)
})

export default router
