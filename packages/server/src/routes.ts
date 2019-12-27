import crypto from 'crypto'
import querystring from 'querystring'
import express from 'express'
import {
  Photon,
  ClientCreateInput, // eslint-disable-line
  UserCreateInput, // eslint-disable-line
  AuthorizationCodeCreateInput // eslint-disable-line
} from '@prisma/photon'

import configurePassport from './auth/configurePassport'

const router = express.Router()
const photon = new Photon()
const passport = configurePassport()

function ensureAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  if (!req.isAuthenticated()) {
    return res.status(401).redirect('/login')
  }

  next()
}

router.get('/register', (req, res) => {
  res.render('register', {})
})

router.post('/register', async (req, res) => {
  try {
    await photon.connect()

    const data: ClientCreateInput = req.body

    data.client_id = crypto.randomBytes(32).toString('hex')
    data.client_secret = crypto.randomBytes(256).toString('hex')
    data.user = {
      connect: {
        // @ts-ignore
        id: req.user.id
      }
    }

    const client = await photon.clients.create({
      data
    })

    res.status(200).send(client)
  } catch (error) {
    await photon.disconnect()

    console.log(error)
    res.status(500).send(error)
  }
})

router.get('/login', (req, res) => {
  const query = querystring.stringify(req.query)
  res.render('login', { query })
})

router.post('/login', passport.authenticate('local'), (req, res) => {
  let search = ''

  if (req.headers.referer) {
    const url = new URL(req.headers.referer)

    search = url.search
  }

  res.redirect(`/authorize${search}`)
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

    const data: UserCreateInput = req.body

    data.password = crypto
      .createHash('sha256')
      .update(data.password)
      .digest('hex')

    const user = await photon.users.create({
      data
    })

    res.status(200).send(user)
  } catch (error) {
    console.log(error)
    res.status(500).send(error)
  } finally {
    await photon.disconnect()
  }
})

router.get('/authorize', ensureAuth, async (req, res, next) => {
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
      where: { client_id: req.query.client_id }
    })

    if (!client) {
      return res.send('Invalid client')
    }

    if (req.query.redirect_uri !== client.redirect_uri) {
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

router.post('/authorize/:action', ensureAuth, async (req, res) => {
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

  await photon.connect()

  const clientId = typeof params.client_id === 'string' && params.client_id

  const data: AuthorizationCodeCreateInput = {
    code: crypto.randomBytes(32).toString('hex'),
    scope: '',
    user: {
      connect: {
        // @ts-ignore
        id: req.user.id
      }
    },
    client: {
      connect: {
        client_id: clientId
      }
    }
  }

  const authorizationCode = await photon.authorizationCodes.create({
    data
  })

  const query = {
    code: authorizationCode.code,
    state: params.state
  }

  if (!params.state) {
    delete query.state
  }

  res.redirect(`${params.redirect_uri}?${querystring.stringify(query)}`)
})

router.post('/token', ensureAuth, async (req, res) => {
  const grantTypes = ['authorization_code', 'client_credentials']

  if (!req.body.client_id) {
    return res.status(400).send({
      error: 'invalid_request',
      error_description: 'Missing required parameter client_id'
    })
  }

  if (!req.body.grant_type || !grantTypes.includes(req.body.grant_type)) {
    return res.status(400).send({
      error: 'invalid_request',
      error_description: `grant_type should be ${grantTypes.join(' or ')}`
    })
  }

  if (!req.body.redirect_uri) {
    return res.status(400).send({
      error: 'invalid_request',
      error_description: 'Missing required parameter redirect_uri'
    })
  }

  if (!req.body.code) {
    return res.status(400).send({
      error: 'invalid_request',
      error_description: 'Missing required parameter code'
    })
  }

  if (
    !req.headers.authorization ||
    !req.headers.authorization.includes('Basic')
  ) {
    res
      .status(400)
      .send({
        error: 'invalid_request',
        error_description: 'Missing required Authorization Header'
      })
      .setHeader('WWW-Authenticate', 'Basic')
  }

  const base64Credentials = req.headers.authorization.split(' ')[1]
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii')
  const [clientId, clientSecret] = credentials.split(':')

  const client = await photon.clients.findOne({
    where: { client_id: clientId }
  })

  if (!client) {
    return res
      .status(401)
      .send({ error: 'invalid client', error_description: '' })
      .setHeader('WWW-Authenticate', 'Basic')
  }

  if (client.client_secret !== clientSecret) {
    return res.status(400).send({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    })
  }

  if (req.body.redirect_uri !== client.redirect_uri) {
    return res.status(400).send({
      error: 'invalid_grant',
      error_description: 'Invalid redirect_uri'
    })
  }

  const authorizationCode = await photon.authorizationCodes.findOne({
    where: { code: req.body.code }
  })

  if (!authorizationCode) {
    return res.status(400).send({
      error: 'invalid_grant',
      error_description: 'Invalid authorization code'
    })
  }

  await photon.authorizationCodes.delete({
    where: { code: authorizationCode.code }
  })

  // verify if the code is expired

  /**
   if (!authorizationCode is expired) {
    return res.status(400).send({
      error: 'invalid_grant',
      error_description: 'Authorization code is expired'
    })
  }
  */

  const accesToken = await photon.accessTokens.create({
    data: {
      token: crypto.randomBytes(32).toString('hex'),
      scope: '',
      user: {
        connect: {
          // @ts-ignore
          id: req.user.id
        }
      },
      client: {
        connect: {
          client_id: clientId
        }
      }
    }
  })

  const refreshToken = await photon.refreshTokens.create({
    data: {
      token: crypto.randomBytes(32).toString('hex'),
      scope: '',
      user: {
        connect: {
          // @ts-ignore
          id: req.user.id
        }
      },
      client: {
        connect: {
          client_id: clientId
        }
      }
    }
  })

  res.status(200).send({
    access_token: accesToken.token,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken.token
  })
})

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
