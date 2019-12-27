import http from 'http'
import path from 'path'
import express from 'express'
import session from 'express-session'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import routes from './routes'
import * as auth from './auth'

const app = express()
const server = http.createServer(app)
const passport = auth.configurePassport()

app.set('views', path.resolve(__dirname, 'views'))
app.set('view engine', 'pug')
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(
  session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true
    }
  })
)
app.use(passport.initialize())
app.use(passport.session())

passport.use(auth.strategies.localStrategy)
passport.serializeUser(auth.serializers.serializeUser)
passport.deserializeUser(auth.serializers.deserializeUser)

app.use(routes)

app.use(function(
  err: Error,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

async function main() {
  server.listen(5000, () => {
    console.log('Server listening on http://localhost:5000')
  })
}

if (!module.parent) {
  main()
}

export default server
