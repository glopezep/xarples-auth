import { Strategy } from 'passport-local'
import { Photon } from '@prisma/photon'

const photon = new Photon()

export default new Strategy(async (username, password, done) => {
  try {
    await photon.connect()

    const user = await photon.users.findOne({
      where: { username },
      select: {
        id: true,
        username: true,
        password: true
      }
    })

    console.log(user)
    console.log(password)

    if (!user || user.password !== password) {
      return done(null, false, { message: 'Incorrect username or password' })
    }

    done(null, user)
  } catch (error) {
    return done(error, null)
  } finally {
    await photon.disconnect()
  }
})
