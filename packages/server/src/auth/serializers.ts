import { User, Photon } from '@prisma/photon' // eslint-disable-line

const photon = new Photon()

export function serializeUser(user: User, done: any) {
  done(null, user.id)
}

export async function deserializeUser(id: string, done: any) {
  const user = await photon.users.findOne({
    where: { id }
  })

  done(null, user)
}
