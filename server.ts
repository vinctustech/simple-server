import express, { Request, Response, NextFunction } from 'express'
import { sign, verify } from 'jsonwebtoken'
import * as bcrypt from 'bcrypt'
import * as dotenv from 'dotenv'
import cookieParser from 'cookie-parser'
import compress from 'compression'
import cors from 'cors'
import dayjs from 'dayjs'

// import jwt from "express-jwt";

dotenv.config()

const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) return res.status(401).json({ error: 'missing bearer token' })

  verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'error verifying access token' })

    res.locals.user = user
    next()
  })
}

const app = express()
const port = 8080

app.use(
  cookieParser(),
  compress(),
  cors({
    origin: /http:\/\/localhost:.*/,
    credentials: true,
  }),
  express.json()
)

const users = []

const data = [
  {
    email: 'user1@company.com',
    data: 'asdf',
  },
  {
    email: 'user2@company.com',
    data: 'zxcv',
  },
  {
    email: 'user1@company.com',
    data: 'asdfasdf',
  },
  {
    email: 'user2@company.com',
    data: 'zxcvzxcv',
  },
]

app.get('/users', (req, res) => {
  res.json(users)
})

app.get('/data', authenticateToken, (req, res) => {
  res.json(data.filter((record) => record.email === res.locals.user.email))
})

app.post('/users', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const user = { email: req.body.email, password: hashedPassword }

    users.push(user)
    res.status(201).json({})
  } catch {
    res.status(500).json({})
  }
})

export const generateAccessToken = (user) =>
  sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s' })

//let refreshTokens = []  //todo invalidate refresh token???

app.get('/auth/refresh', (req, res) => {
  if (!req.cookies?.refreshToken) return res.status(401).json({ error: 'no refresh token' })

  const refreshToken = req.cookies.refreshToken

  //if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403) //todo invalidate refresh token???

  console.log(refreshToken)
  verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'error verifying refresh token' })

    console.log(user)
    const accessToken = generateAccessToken({ email: user.email })

    res.json({ accessToken })
  })
})

app.get('/auth/logout', (req, res) => {
  if (!req.cookies?.refreshToken) return res.status(401).json({ error: 'no refresh token' })

  //const refreshToken = req.cookies.refreshToken //todo invalidate refresh token???

  //if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403) //todo invalidate refresh token???

  //refreshTokens = refreshTokens.filter((token) => token !== refreshToken) //todo invalidate refresh token???
  // res.cookie('refreshToken', '', {
  //   maxAge: 0,
  //   //secure: true, //todo
  //   httpOnly: true,
  // })
  res.clearCookie('refreshToken', { httpOnly: true }) // todo: When using in production with SSL, you need to specify the domain: https://stackoverflow.com/questions/27978868/destroy-cookie-nodejs
  res.status(200).json({})
})

app.post('/auth/login', async (req, res) => {
  const user = users.find((user) => user.email === req.body.email)

  if (!user) return res.status(400).json({ error: `cannot find user '${req.body.email}'` })

  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const email = req.body.email
      const user = { email }
      const accessToken = generateAccessToken(user)
      const refreshToken = sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '28d' })

      //refreshTokens.push(refreshToken) //todo invalidate refresh token???
      res.cookie('refreshToken', refreshToken, {
        expires: dayjs().add(28, 'days').toDate(),
        secure: false, //todo
        httpOnly: true,
      })
      res.json({ accessToken })
    } else res.status(401).json({ error: 'wrong password' })
  } catch {
    res.status(500).send()
  }
})

app.listen(port, () => {
  return console.log(`Express is listening at http://localhost:${port}`)
})
