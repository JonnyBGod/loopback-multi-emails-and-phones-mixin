# loopback-multi-emails-and-phones-mixin (WIP)

[![NPM version][npm-image]][npm-url] [![NPM downloads][npm-downloads-image]][npm-downloads-url]
[![devDependency Status](https://david-dm.org/JonnyBGod/loopback-multi-emails-and-phones-mixin/dev-status.svg)](https://david-dm.org/JonnyBGod/loopback-multi-emails-and-phones-mixin#info=devDependencies)
[![Build Status](https://img.shields.io/travis/JonnyBGod/loopback-multi-emails-and-phones-mixin/master.svg?style=flat)](https://travis-ci.org/JonnyBGod/loopback-multi-emails-and-phones-mixin)

[![MIT license][license-image]][license-url]
[![Gitter Chat](https://img.shields.io/gitter/room/nwjs/nw.js.svg)](https://gitter.im/loopback-multi-emails-and-phones-mixin/Lobby)

##Features

- multiple emails
- multiple phones

##Installation

```bash
npm install loopback-multi-emails-and-phones-mixin --save
```

##How to use


Add the mixins property to your server/model-config.json like the following:

```json
{
  "_meta": {
    "sources": [
      "loopback/common/models",
      "loopback/server/models",
      "../common/models",
      "./models"
    ],
    "mixins": [
      "loopback/common/mixins",
      "../node_modules/loopback-multi-emails-and-phones-mixin",
      "../common/mixins"
    ]
  }
}

```

To use with your Models add the mixins attribute to the definition object of your model config.

```json
{
  "name": "user",
  "base": "User",
  "properties": {
    "name": {
      "type": "string",
    }
  },
  "mixins": {
    "MultiEmailsAndPhones": true
  }
}
```

## LIMITATIONS

 - Currently only working with memory and mongodb connectors. [Filter on level 2 properties](https://github.com/strongloop/loopback/issues/517)

## TODO

 - Fix pending tests

## License

[MIT](LICENSE)

[npm-image]: https://img.shields.io/npm/v/loopback-multi-emails-and-phones-mixin.svg
[npm-url]: https://npmjs.org/package/loopback-multi-emails-and-phones-mixin
[npm-downloads-image]: https://img.shields.io/npm/dm/loopback-multi-emails-and-phones-mixin.svg
[npm-downloads-url]: https://npmjs.org/package/loopback-multi-emails-and-phones-mixin
[bower-image]: https://img.shields.io/bower/v/loopback-multi-emails-and-phones-mixin.svg
[bower-url]: http://bower.io/search/?q=loopback-multi-emails-and-phones-mixin
[dep-status-image]: https://img.shields.io/david/angulartics/loopback-multi-emails-and-phones-mixin.svg
[dep-status-url]: https://david-dm.org/angulartics/loopback-multi-emails-and-phones-mixin
[license-image]: http://img.shields.io/badge/license-MIT-blue.svg
[license-url]: LICENSE
[slack-image]: https://loopback-multi-emails-and-phones-mixin.herokuapp.com/badge.svg
[slack-url]: https://loopback-multi-emails-and-phones-mixin.herokuapp.com