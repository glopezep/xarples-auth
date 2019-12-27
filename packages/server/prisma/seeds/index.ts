import crypto from 'crypto'
import {
  Photon,
  UserCreateInput, // eslint-disable-line
  User, // eslint-disable-line
  ClientCreateInput // eslint-disable-line
} from '@prisma/photon'

const photon = new Photon()

async function createUser() {
  const user: UserCreateInput = {
    email: 'guillermolopez2529@gmail.com',
    name: 'Guillermo Lopez',
    username: 'glopezep',
    password: '1234'
  }

  user.password = crypto
    .createHash('sha256')
    .update(user.password)
    .digest('hex')

  return photon.users.create({
    data: user
  })
}

async function createClient(user: User) {
  const client: ClientCreateInput = {
    client_id: crypto.randomBytes(32).toString('hex'),
    client_secret: crypto.randomBytes(256).toString('hex'),
    description: 'A random client description',
    name: 'Instagreen',
    redirect_uri: 'http://localhost:3000/callback',
    homepage_url: 'http://localhost:3000',
    user: {
      connect: {
        id: user.id
      }
    }
  }

  return photon.clients.create({
    data: client
  })
}

async function seeds() {
  await photon.connect()
  const user = await createUser()
  await createClient(user)
  await photon.disconnect()
}

seeds()
