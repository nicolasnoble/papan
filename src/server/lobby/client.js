'use strict'

const path = require('path')
const grpc = require('grpc')
const merge = require('deepmerge')
const _ = require('lodash')
const PapanServerUtils = require('../common/utils.js')
const protoLoader = require('../common/proto.js')

class LobbyClient {
  constructor ({ lobbyProto, grpcClient, clientInterface }) {
    this.lobbyProto = lobbyProto
    this.grpcClient = grpcClient
    this.clientInterface = clientInterface
    this.ActionFields = lobbyProto.rootProto.lookupType('PapanLobby.Action').fields
    this.UpdateFields = lobbyProto.rootProto.lookupType('PapanLobby.Update').fields
    this.LobbyActionFields = lobbyProto.rootProto.lookupType('PapanLobby.LobbyAction').fields
    this.LobbyUpdateFields = lobbyProto.rootProto.lookupType('PapanLobby.LobbyUpdate').fields

    const mapping = {
      'PapanLobby.JoinLobby': 'join',
      'PapanLobby.StartWatchingLobbies': 'startWatchingLobbies',
      'PapanLobby.StopWatchingLobbies': 'stopWatchingLobbies'
    }
    Object.keys(mapping).forEach(type => {
      this[type] = this[mapping[type]]
    })

    Object.keys(this.ActionFields).forEach(fieldName => {
      const type = 'PapanLobby.' + this.ActionFields[fieldName].type
      if (this[type]) return
      this[type] = (message, metadata) => {
        const obj = {}
        obj[fieldName] = message
        this.subscribedWrite(obj)
      }
    })

    Object.keys(this.LobbyActionFields).forEach(fieldName => {
      const type = 'PapanLobby.' + this.LobbyActionFields[fieldName].type
      if (this[type]) return
      this[type] = (message, metadata) => {
        const obj = {}
        obj[fieldName] = message
        const lobby = this.lobbies[metadata.id]
        if (lobby) lobby.call.write(obj)
      }
    })

    this.lobbies = {}
  }

  close () {
    if (this.subscription) this.subscription.cancel()
    if (this.lobbiesWatcher) this.lobbiesWatcher.cancel()
    Object.keys(this.lobbies).forEach(key => {
      this.lobbies[key].call.cancel()
    })
  }

  getAuthMetadata () {
    let metadata = new grpc.Metadata()
    if (this.papanCode) {
      metadata.set('papan-code', this.papanCode)
      this.papanCode = null
    } else if (this.papanSession) {
      metadata.set('papan-session', this.papanSession)
    }
    return metadata
  }

  errorCatcher (call, retry, handler) {
    call.on('error', err => {
      if (err.code === grpc.status.UNAUTHENTICATED) {
        this.clientInterface.setLobbyConnectionStatus('AUTHENTICATING')
        this.clientInterface.getAuthorizationCode()
          .then(code => {
            this.papanCode = code
            retry()
          })
          .catch(err => {
            err.code = grpc.status.UNAUTHENTICATED
            call.emit('error', err)
          })
      } else {
        if (handler) handler(err)
      }
    })
  }

  metadataCatcher (call, handler) {
    call.on('metadata', metadata => {
      const session = metadata.get('papan-session')
      if (session.length === 1) {
        this.papanSession = session[0]
      }
      handler(metadata)
    })
  }

  subscribe () {
    const call = this.grpcClient.Subscribe()
    this.errorCatcher(call, () => this.subscribe(), console.log)
    this.metadataCatcher(call, console.log)
    call.on('status', status => {
      console.log(status)
    })
    call.on('end', () => {
      console.log('end')
    })
    call.on('data', data => {
      const UpdateField = this.UpdateFields[data.update]
      let typeName = 'PapanLobby.' + UpdateField.type
      switch (data.update) {
        case 'subscribed':
          this.clientInterface.setLobbyConnectionStatus('CONNECTED')
          // falls through
        default:
          this.clientInterface[typeName](data[data.update])
          break
      }
    })
    this.subscription = call
  }

  join (data) {
    const call = this.grpcClient.Lobby()
    if (!data) data = {}
    let id = data.id
    if (id) {
      this.lobbies[id] = { call: call }
    }

    this.errorCatcher(call, () => this.join({ id: id }), console.log)
    this.metadataCatcher(call, console.log)
    call.on('status', status => {
      console.log(status)
    })
    call.on('end', () => {
      console.log('end')
    })
    call.on('data', data => {
      let justJoined = false
      const LobbyUpdateField = this.LobbyUpdateFields[data.update]
      let typeName = 'PapanLobby.' + LobbyUpdateField.type
      if (!id && data.update === 'info') {
        justJoined = true
        id = data.info.id
        this.lobbies[id] = { call: call }
      }
      this.clientInterface[typeName](data[data.update], { id: id })
      if (justJoined) {
        this.clientInterface.joinedLobby(data.info)
      }
    })

    call.write({ join: data })
  }

  subscribedWrite (data) {
    if (this.clientInterface.getLobbyConnectionStatus() !== 'CONNECTED') {
      return
    }

    this.subscription.write(data)
  }

  startWatchingLobbies () {
    if (this.lobbiesWatcher) return
    const call = this.grpcClient.ListLobbies()
    this.lobbiesWatcher = call
    this.errorCatcher(call, () => {
      this.lobbiesWatcher = null
      this.startWatchingLobbies()
    }, console.log)
    this.metadataCatcher(call, console.log)
    call.on('status', status => {
      console.log(status)
    })
    call.on('end', () => {
      console.log('end')
    })
    call.on('data', data => {
      this.clientInterface['PapanLobby.PublicLobbyUpdate'](data)
    })
  }

  stopWatchingLobbies () {
    if (!this.lobbiesWatcher) return
    this.lobbiesWatcher.end()
    this.lobbiesWatcher = null
  }
}

const clientDefaults = Object.freeze({
  connectLocal: false,
  lobbyServer: 'lobby.papan.online',
  lobbyServerPort: 9999,
  useLocalCA: true
})

exports.createClient = (clientInterface, options) => {
  options = _.defaults(options, clientDefaults)
  if (options.connectLocal) {
    options.lobbyServer = 'localhost'
    options.lobbyServerPort = 9999
    options.useLocalCA = true
  }
  const serverAddress = options.lobbyServer + ':' + options.lobbyServerPort
  clientInterface.setLobbyConnectionStatus('CONNECTING')

  const work = [
    PapanServerUtils.readFile(path.join(__dirname, '..', '..', '..', 'certs', 'ca.crt')),
    protoLoader.load('lobby.proto')
  ]

  return Promise.all(work).then(results => {
    const lobbyProto = results[1].PapanLobby
    let client
    const sslCreds = options.useLocalCA ? grpc.credentials.createSsl(results[0]) : grpc.credentials.createSsl()
    const callCreds = grpc.credentials.createFromMetadataGenerator((args, callback) => {
      const metadata = client.getAuthMetadata()
      callback(null, metadata)
    })
    const creds = grpc.credentials.combineChannelCredentials(sslCreds, callCreds)
    const localChannelOptions = {
      'grpc.ssl_target_name_override': 'localhost'
    }
    let channelOptions = {}
    if (options.useLocalCA) channelOptions = merge(channelOptions, localChannelOptions)

    const grpcClient = new lobbyProto.PlayerLobbyService(serverAddress, creds, channelOptions)
    client = new LobbyClient({ lobbyProto: results[1], grpcClient: grpcClient, clientInterface: clientInterface })
    client.subscribe()

    return client
  })
}
