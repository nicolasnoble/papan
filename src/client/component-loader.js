'use strict'

class ComponentLoader {
  constructor () {
    global.lobbyInterface.on('games', games => Object.keys(games).forEach(key => this._onGameInfo(games[key])))
    global.lobbyInterface.on('requestGameInfo', this._requestGameInfo.bind(this))
    global.lobbyInterface.on('gameInfo', this._onGameInfo.bind(this))
    this._gamesList = {}
    this._gamesByInfoHash = {}
    this._resolvers = {}
    this._torrentsInfo = {}
    this._components = {}
    const parser = new global.DOMParser()
    this._parseString = string => parser.parseFromString(string, 'text/html')
  }

  load (gameInfo) {
    const infoHash = gameInfo.torrent.infoHash
    if (this._components[infoHash]) return this._components[infoHash].promise
    const promises = []
    const globalDeps = gameInfo.json.globalDeps || []
    globalDeps.forEach(dep => {
      if (!global.customElements.get(dep)) {
        return Promise.reject(Error('Missing global dependency: ' + dep))
      }
    })
    promises.push(this._getTorrent(gameInfo.torrent))
    Object.keys(gameInfo.json.deps || {}).forEach(infoHash => {
      if (!this._components[infoHash] && !this._gamesByInfoHash[infoHash]) {
        promises.push(this._loadByHash(infoHash))
      }
    })

    const promise = Promise.all(promises)
    .then(() => {
      Object.keys(gameInfo.json.deps || {}).forEach(depInfoHash => {
        const dst = this._components[infoHash].transforms
        const src = this._components[depInfoHash].transforms
        this._components[infoHash].transforms = global.deepmerge(dst, src)
      })
      this._loadComponent(infoHash)
    })

    this._components[infoHash] = {
      promise: promise,
      transforms: {}
    }

    return promise
  }

  _loadByHash (infoHash) {
    global.lobbyInterface.requestGameInfo(infoHash)
    let torrent
    return new Promise((resolve, reject) => {
      this._resolvers[infoHash] = resolve
    })
    .then(info => this._getTorrent(info.torrent))
    .then(result => {
      torrent = result
      if (torrent.infoHash !== infoHash) return Promise.reject(Error('Expected ' + infoHash + ' but got ' + torrent.infoHash))
      return this._getFile(infoHash, 'game.json')
    })
    .then(buffer => this.load({
      json: JSON.parse(buffer.toString()),
      torrent: {
        infoHash: torrent.infoHash,
        magnetURI: torrent.magnetURI,
        torrentFile: torrent.torrentFile
      }
    }))
  }

  _getTorrent (torrentInfoOrHash) {
    let infoHash
    let torrentFile
    if (typeof torrentInfoOrHash === 'string') {
      infoHash = torrentInfoOrHash
    } else {
      infoHash = torrentInfoOrHash.infoHash
      torrentFile = torrentInfoOrHash.torrentFile
    }
    const alreadyDownloading = this._torrentsInfo[infoHash]
    if (alreadyDownloading) {
      return alreadyDownloading.torrentPromise
    }
    if (!torrentFile) return Promise.reject(Error('No torrent file for ' + infoHash))
    this._torrentsInfo[infoHash] = {}
    const promise = new Promise((resolve, reject) => {
      const torrentResolve = resolve
      this._torrentsInfo[infoHash].filesPromise = new Promise((resolve, reject) => {
        const filesResolve = resolve
        global.webTorrentClient.add(torrentFile, torrent => {
          torrentResolve(torrent)
          torrent.on('done', () => filesResolve(torrent.files))
        })
      })
    })
    this._torrentsInfo[infoHash].torrentPromise = promise
    return promise
  }

  _onGameInfo (info) {
    let infoHash = info.torrent.infoHash
    this._gamesList[info.id] = info
    this._gamesByInfoHash[infoHash] = info
    if (this._resolvers[infoHash]) {
      this._resolvers[infoHash](info)
      delete this._resolvers[infoHash]
    }
  }

  _requestGameInfo (infoHash) {
    let game = this._gamesByInfoHash[infoHash]
    if (game) global.lobbyInterface.sendGameInfo(game)
  }

  _getFile (infoHash, filename) {
    return this._getTorrent(infoHash)
    .then(torrent => new Promise((resolve, reject) => {
      let found = false
      const baseName = torrent.name + '/'
      torrent.files.forEach(file => {
        const name = file.path.slice(baseName.length).replace('\\', '/')
        if (name === filename) {
          file.getBuffer((err, buffer) => {
            if (err) reject(err)
            resolve(buffer)
          })
          found = true
        }
      })
      if (!found) reject(Error('Torrent ' + infoHash + ' doesn\'t have a file named ' + filename))
    }))
  }

  _loadComponent (infoHash) {
    this._getFile(infoHash, 'game.json')
    .then(file => {
      const json = JSON.parse(file.toString())
      const webComponent = json.webcomponent
      if (typeof webComponent === 'string' && webComponent.length !== 0) {
        return this._loadHTML(infoHash, webComponent)
      }
      return Promise.reject(Error('Torrent ' + infoHash + ' has no registered web component.'))
    })
    .then(doc => new Promise((resolve, reject) => {
      const serialized = doc.firstChild.innerHTML
      const component = document.createElement('link')
      component.setAttribute('rel', 'import')
      component.setAttribute('href', this._encodeToHREF('text/html', global.btoa(serialized)))
      component.onload = () => resolve(infoHash)
      document.head.appendChild(component)
    }))
  }

  _loadHTML (infoHash, filename) {
    return this._getFile(infoHash, filename)
    .then(file => this._transform(infoHash, this._parseString(file.toString())))
  }

  _encodeToHREF (type, base64) {
    const encoded = encodeURIComponent(base64)
    return 'data:' + type + ';charset=utf-8;base64,' + encoded
  }

  _transformArrayAndAttach (infoHash, elements, base) {
    if (!base) return Promise.resolve(base)
    const promises = []
    for (let i = 0; i < elements.length; i++) {
      if (elements[i]) promises.push(this._transform(infoHash, elements[i]))
    }
    return Promise.all(promises)
    .then(newElements => {
      let child = base.firstChild
      while (child) {
        base.removeChild(child)
        child = base.firstChild
      }
      newElements.forEach(element => {
        if (element) base.appendChild(element)
      })
      return base
    })
  }

  _transform (infoHash, element) {
    const tagName = element.nodeName.toLowerCase()
    const transform = this._components[infoHash].transforms[tagName]
    let newElement
    let promise
    let processChildren = true
    if (transform) {
      newElement = element.ownerDocument.createElement(transform)
      const attrs = element.attributes
      for (let i = attrs.length - 1; i >= 0; i--) {
        newElement.setAttribute(attrs[i].name, attrs[i].value)
      }
    } else {
      newElement = element
      const getAttribute = element.getAttribute ? element.getAttribute.bind(element) : () => null
      const id = getAttribute('id')
      let src = getAttribute('src')
      let href = getAttribute('href')
      switch (tagName) {
        case 'link':
          if (getAttribute('rel') === 'import') {
            switch (getAttribute('type')) {
              case 'css':
                processChildren = false
                promise = this._getFile(infoHash, href)
                .then(file => {
                  const element = newElement.ownerDocument.createElement('style')
                  element.text = file.toString()
                  return element
                })
                break
              default:
                newElement = null
            }
          }
          break
        case 'dom-module':
        case 'template':
          if (id) {
            this._components[infoHash].transforms[id] = infoHash + '-' + id
            element.setAttribute('id', infoHash + '-' + id)
          }
          break
        case 'script':
          processChildren = false
          const attachScript = (element, script) => {
            let child = element.firstChild
            while (child) {
              element.removeChild(child)
              child = element.firstChild
            }
            element.appendChild(element.ownerDocument.createTextNode(script))
          }
          if (src) {
            promise = this._getFile(infoHash, src)
            .then(file => {
              const newScript = this._transformScript(infoHash, file.toString())
              element.removeAttribute('src')
              attachScript(element, newScript)
              return element
            })
          } else {
            const newScript = this._transformScript(infoHash, element.text)
            attachScript(element, newScript)
          }
          break
        case 'img':
          if (src && !src.startsWith('data:')) {
            promise = this._getFile(infoHash, src)
            .then(file => {
              const mimeTypes = {
                'gif': 'image/gif',
                'png': 'image/png',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'bmp': 'image/bmp',
                'svg': 'image/svg+xml'
              }
              let mimeType = 'text/plain'
              Object.keys(mimeTypes).forEach(extension => {
                if (src.endsWith('.' + extension)) {
                  mimeType = mimeTypes[extension]
                }
              })
              element.setAttribute('src', this._encodeToHREF(mimeType, file.toString('base64')))
              return element
            })
          }
          break
      }
    }
    if (!promise) {
      promise = Promise.resolve(newElement)
    }
    if (processChildren) {
      return promise
      .then(newElement => this._transformArrayAndAttach(infoHash, element.children, newElement))
    } else {
      return promise
    }
  }

  _transformScript (infoHash, text) {
    const pluginName = 'papan-plugin-' + infoHash
    const transforms = this._components[infoHash].transforms
    const plugin = () => ({
      visitor: {
        StringLiteral (path) {
          const transform = transforms[path.node.value]
          if (transform) path.node.value = transform
        }
      }
    })
    global.Babel.registerPlugin(pluginName, plugin)
    return global.Babel.transform(text, { presets: ['es2017', 'stage-0', 'react'], plugins: [ pluginName ] }).code
  }
}

this.componentLoader = new ComponentLoader()
