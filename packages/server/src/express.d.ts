import { User } from '@prisma/photon' // eslint-disable-line

declare global {
  namespace Express {
    interface User {
      id: string
    }

    interface Request {
      user?: User
    }
  }
}
