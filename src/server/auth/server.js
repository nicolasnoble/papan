'use strict'

const path = require('path')
const env = require('process').env
const express = require('express')
const bodyParser = require('body-parser')
const winston = require('winston')
const expressWinston = require('express-winston')
const session = require('express-session')
const pg = require('pg')
const PGSession = require('connect-pg-simple')(session)
const assert = require('assert')
const forge = require('node-forge')
const pki = forge.pki
const crypto = require('crypto')
const serializeError = require('serialize-error')

const passport = require('passport')

const userDB = require('./userdb.js')
const PapanServerUtils = require('../common/utils.js')

const root = path.normalize(path.join(__dirname, '..', '..', '..'))

const builtInAuthProviders =
  [
    {
      configName: 'googleAuthConfig',
      src: './providers/google-auth.js'
    },
    {
      configName: 'facebookAuthConfig',
      src: './providers/facebook-auth.js'
    },
    {
      configName: 'twitterAuthConfig',
      src: './providers/twitter-auth.js'
    },
    {
      configName: 'steamAuthConfig',
      src: './providers/steam-auth.js'
    }
  ]

exports.registerServer = (app, config) => {
  let authentications = []
  let users
  let registerProvider
  let caKey = null
  let caCrtBuffer = null
  let caCrtSubject = null
  let caStore = pki.createCaStore()

  if (!config) config = {}
  if (!config.pgConfig) config.pgConfig = {}
  config.pgConfig.user = config.pgConfig.user || env.PGUSER
  config.pgConfig.password = config.pgConfig.password || env.PGPASSWORD
  config.pgConfig.host = config.pgConfig.host || env.PGHOST
  config.pgConfig.port = config.pgConfig.port || env.PGPORT
  config.pgConfig.database = config.pgConfig.database || env.PGDATABASE

  if (config.caCrt) {
    const caCrt = pki.certificateFromPem(config.caCrt)
    do {
      if (!caCrt) break
      const basicConstraints = caCrt.getExtension('basicConstraints')
      if (!basicConstraints || !basicConstraints.cA) break
      const subject = caCrt.subject
      const O = subject.getField('O')
      if (!O || O.value !== 'Papan') break
      caStore.addCertificate(caCrt)
      caCrtBuffer = config.caCrt
      caCrtSubject = caCrt.subject
    } while (false)
  }

  if (config.caKey && caCrtBuffer) {
    caKey = pki.privateKeyFromPem(config.caKey)
  }

  return Promise.resolve(userDB.create(config.pgConfig)).then(createdUsers => {
    // We need to create and migrate the database first thing before going on with the rest of the work.
    users = createdUsers
    return users.initialize()
  }).then(() => new Promise((resolve, reject) => {
    // logger
    app.use(expressWinston.logger({
      transports: [
        new winston.transports.Console({
          json: false,
          colorize: true
        })
      ],
      meta: true,
      expressFormat: true
    }))

    // session management
    const pgPool = new pg.Pool(config.pgConfig)
    app.use(session({
      store: new PGSession({
        pool: pgPool,
        tableName: 'session'
      }),
      secret: config.httpConfig.secret,
      resave: false,
      saveUninitialized: false
    }))

    // we'll do ajax
    app.use(bodyParser.json())

    // passport
    app.use(passport.initialize())
    app.use(passport.session())

    passport.serializeUser((user, done) => users.serialize(user).then(id => done(null, id)).catch(err => done(err, false)))
    passport.deserializeUser((id, done) => users.deserialize(id).then(user => done(null, user)).catch(err => done(err, false)))
    passport.authenticated = returnURL => {
      return (req, res, next) => {
        if (req.isAuthenticated()) return next()
        req.session.returnURL = returnURL || req.returnURL || req.originalUrl
        res.redirect('/render/login')
      }
    }

    // Static files
    function sendRoot (res) {
      res.sendFile(path.join(root, 'render', 'auth-index.html'))
    }
    app.use('/src/common', express.static(path.join(root, 'src', 'common')))
    app.use('/src/client/auth', express.static(path.join(root, 'src', 'client', 'auth')))
    app.use('/bower_components', express.static(path.join(root, 'bower_components')))
    app.use('/docs', express.static(path.join(root, 'docs')))
    app.use('/node_modules', express.static(path.join(root, 'node_modules')))
    app.use('/template', express.static(path.join(root, 'template')))
    app.get('/', (req, res) => res.redirect('/render/main'))
    app.get('/render/main', (req, res) => sendRoot(res))
    app.get('/render/login', (req, res) => sendRoot(res))
    app.get('/render/profile', (req, res) => sendRoot(res))
    app.get('/certs/ca.crt', (req, res) => {
      if (caCrtBuffer) {
        res.type('crt')
        res.send(caCrtBuffer)
      } else {
        res.sendFile(path.join(root, 'certs', 'ca.crt'))
      }
    })

    // AJAX
    app.get('/profile/data', (req, res) => res.json(
      req.isAuthenticated() ? req.user.dataValues : {}
    ))
    app.get('/auth/getcode',
      passport.authenticated(),
      (req, res, next) => PapanServerUtils.generateToken({ prefix: 'CODE' })
        .then(token => users.addTemporaryCode(req.user, token))
        .then(token => res.json({ code: token.dataValues.id }))
        .catch(err => next(err))
    )
    app.get('/auth/forwardcode',
      passport.authenticated(),
      (req, res, next) => (req.query.returnURL && req.query.returnURL.indexOf('?') < 0
        ? PapanServerUtils.generateToken({ prefix: 'CODE' })
        : Promise.reject(Error('Invalid returnURL query parameter'))
      ).then(token => users.addTemporaryCode(req.user, token))
        .then(token => res.redirect(req.query.returnURL + '?code=' + token.dataValues.id))
        .catch(err => next(err))
    )
    app.post('/exchange', (req, res, next) => {
      let code = req.body.code
      let userId = -1
      users.findUserByTemporaryCode(code)
        .then(user => {
          if (user) {
            userId = user.dataValues.id
            return users.revokeTemporaryCode(code)
          } else {
            return Promise.reject(Error('user not found'))
          }
        }).then(() => res.json({ userId: userId }))
        .catch(err => next(err))
    })
    app.get('/auth/available', (req, res) => res.json({ providers: authentications }))
    app.get('/info', (req, res) => res.json({
      authenticated: req.isAuthenticated()
    }))
    app.post('/certs/sign', (req, res) => {
      const csrString = req.body.csr
      let error = null
      do {
        if (!csrString) {
          error = 'No CSR sent'
          break
        }
        const csr = pki.certificationRequestFromPem(csrString)
        if (!csr) {
          error = 'Unable to parse CSR'
          break
        }
        const subject = csr.subject
        const CN = subject.getField('CN')
        const O = subject.getField('O')
        const OU = subject.getField('OU')
        if (!CN || CN.value !== 'localhost') {
          error = 'Invalid CN field in CSR'
          break
        }
        if (!O || O.value !== 'Papan') {
          error = 'Invalid O field in CSR'
          break
        }
        if (!OU || OU.value !== 'Server-Ad-Hoc') {
          error = 'Invalid OU field in CSR'
          break
        }
        if (!csr.verify()) {
          error = 'Couldn\'t verify CSR'
        }
        const cert = pki.createCertificate()
        const now = new Date()
        cert.validity.notBefore = now
        cert.validity.notAfter.setTime(now.getTime() + 5 * 24 * 60 * 60 * 1000)
        cert.setSubject(csr.subject.attributes)
        cert.setIssuer(caCrtSubject.attributes)
        cert.publicKey = csr.publicKey
        crypto.randomBytes(20, (err, buffer) => {
          if (buffer[0] > 127) {
            buffer[0] -= 128
          }
          cert.serialnumber = [...buffer].map(b => b.toString(16)).join('')
          cert.sign(caKey)
          res.json({ cert: pki.certificateToPem(cert) })
        })
      } while (false)
      if (error) {
        res.status(400)
        res.json({ error: error })
      }
    })

    // Auth providers logic
    registerProvider = (provider) => {
      app.get(
        `/auth/${provider.urlFragment}/login`, (req, res, next) => {
          if (req.isAuthenticated()) res.redirect('/render/profile')
          passport.authenticate(provider.create)(req, res, next)
        }
      )
      app.get(
        `/auth/${provider.urlFragment}/connect`, passport.authenticated(), (req, res, next) => {
          passport.authorize(provider.connect)(req, res, next)
        }
      )
      function getReturnURL (req) {
        let returnURL = '/render/profile'
        if (req.session.returnURL) {
          returnURL = req.session.returnURL
          req.session.returnURL = null
        }
        return returnURL
      }
      app.get(
        `/auth/${provider.urlFragment}/callback`,
        (req, res, next) => {
          const isConnecting = req.isAuthenticated()
          let middleware
          if (isConnecting) {
            middleware = passport.authorize(
              provider.connect,
              (err, account) => {
                if (err) return next(err)
                users.addProviderAccount(req.user, account).then(user => {
                  req.logIn(user, err => {
                    if (err) return next(err)
                    res.redirect(getReturnURL(req))
                  })
                }).catch(err => next(err))
              }
            )
          } else {
            middleware = passport.authenticate(
              provider.create,
              (err, user) => {
                if (err) return next(err)
                if (!user) return res.redirect('/render/login')

                req.logIn(user, err => {
                  if (err) return next(err)
                  res.redirect(getReturnURL(req))
                })
              }
            )
          }
          middleware(req, res, next)
        }
      )
    }

    // Logout
    app.get('/logout', (req, res) => {
      req.logOut()
      res.redirect('/')
    })

    // And finally, catch-all error 500, for future expansion.
    app.use((err, req, res, next) => {
      res.status(500).send(serializeError(err))
    })

    resolve()
  })).then(() => {
    // Contruction of all the promises we're going to wait for to start the server.
    const promises = []
    try {
      const authProviders = builtInAuthProviders.concat(config.externalAuthProviders || [])
      authProviders.forEach(providerValues => {
        if (!config[providerValues.configName]) return
        const registerPromise = require(providerValues.src).register(passport, users, config)
        promises.push(
          registerPromise.then(provider => {
            assert(provider.urlFragment.indexOf('#') === -1)
            authentications.push({
              provider: provider.urlFragment,
              loginPath: `/auth/${provider.urlFragment}/login`,
              connectPath: `/auth/${provider.urlFragment}/connect`
            })
            registerProvider(provider)
            return Promise.resolve()
          }
          ))
      })
    } catch (err) {
      promises.push(Promise.reject(err))
    }
    return Promise.all(promises)
  })
}
