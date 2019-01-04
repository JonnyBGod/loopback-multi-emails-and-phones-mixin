'use strict';
const loopback = require('loopback/lib/loopback');
const g = require('strong-globalize')();
const speakeasy = require('speakeasy');
const utils = require('loopback/lib/utils');
const assert = require('assert');
const path = require('path');
const qs = require('querystring');
const phone = require('phone');

const debug = require('debug')('core:phoneNumber');

module.exports = function(PhoneNumber) {
  /**
   * Verify a user's identity by sending them a confirmation message.
   * NOTE: Currently only phone verification is supported
   *
   * ```js
   * var verifyOptions = {
   *   type: 'phone',
   *   from: 'noreply@example.com'
   *   template: 'verify.ejs',
   *   redirect: '/',
   *   generateVerificationToken: function (user, options, cb) {
   *     cb('random-token');
   *   }
   * };
   *
   * user.verify(verifyOptions);
   * ```
   *
   * NOTE: the User.getVerifyOptions() method can also be used to ease the
   * building of identity verification options.
   *
   * ```js
   * var verifyOptions = MyUser.getVerifyOptions();
   * user.verify(verifyOptions);
   * ```
   *
   * @options {Object} verifyOptions
   * @property {String} type Must be `'phone'` in the current implementation.
   * @property {Function} phoner A phoner function with a static `.send() method.
   *  The `.send()` method must accept the verifyOptions object, the method's
   *  remoting context options object and a callback function with `(err, phone)`
   *  as parameters.
   *  Defaults to provided `userModel.phone` function, or ultimately to LoopBack's
   *  own phoner function.
   * @property {String} to Email address to which verification phone is sent.
   *  Defaults to user's phone. Can also be overriden to a static value for test
   *  purposes.
   * @property {String} from Sender phone address
   *  For example `'noreply@example.com'`.
   * @property {String} subject Subject line text.
   *  Defaults to `'Thanks for Registering'` or a local equivalent.
   * @property {String} text Text of phone.
   *  Defaults to `'Please verify your phone by opening this link in a web browser:`
   *  followed by the verify link.
   * @property {Object} headers Email headers. None provided by default.
   * @property {String} template Relative path of template that displays verification
   *  page. Defaults to `'../../templates/verify.ejs'`.
   * @property {Function} templateFn A function generating the phone HTML body
   *  from `verify()` options object and generated attributes like `options.redirect`.
   *  It must accept the verifyOptions object, the method's remoting context options
   *  object and a callback function with `(err, html)` as parameters.
   *  A default templateFn function is provided, see `createVerificationEmailBody()`
   *  for implementation details.
   * @property {String} redirect Page to which user will be redirected after
   *  they verify their phone. Defaults to `'/'`.
   *  `http://host:port/restApiRoot/userRestPath/confirm?uid=userId&redirect=/``
   * @property {String} host The API host. Defaults to app's host or `localhost`.
   * @property {String} protocol The API protocol. Defaults to `'http'`.
   * @property {Number} port The API port. Defaults to app's port or `3000`.
   * @property {String} restApiRoot The API root path. Defaults to app's restApiRoot
   *  or `'/api'`
   * @property {Function} generateVerificationToken A function to be used to
   *  generate the verification token.
   *  It must accept the verifyOptions object, the method's remoting context options
   *  object and a callback function with `(err, hexStringBuffer)` as parameters.
   *  This function should NOT add the token to the user object, instead simply
   *  execute the callback with the token! User saving and phone sending will be
   *  handled in the `verify()` method.
   *  A default token generation function is provided, see `generateVerificationToken()`
   *  for implementation details.
   * @callback {Function} cb Callback function.
   * @param {Object} options remote context options.
   * @param {Error} err Error object.
   * @param {Object} object Contains phone, token, uid.
   * @promise
   */

  PhoneNumber.prototype.verify = function(user, verifyOptions, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    let phoneNumber = this;
    const phoneNumberModel = this.constructor;
    const userModel = user.constructor;
    const registry = phoneNumberModel.registry;
    verifyOptions = Object.assign({}, verifyOptions);
    // final assertion is performed once all options are assigned
    assert(typeof verifyOptions === 'object',
      'verifyOptions object param required when calling phoneNumber.verify()');

    // Shallow-clone the options object so that we don't override
    // the global default options object
    verifyOptions = Object.assign({}, verifyOptions);

    // Set a default template generation function if none provided
    verifyOptions.templateFn = verifyOptions.templateFn || createVerificationEmailBody;

    // Set a default token generation function if none provided
    verifyOptions.generateVerificationToken = verifyOptions.generateVerificationToken ||
      PhoneNumber.generateVerificationToken;

    // Set a default phoner function if none provided
    verifyOptions.phoner = verifyOptions.phoner || userModel.phone ||
      registry.getModelByType(loopback.Email);

    const pkName = phoneNumberModel.definition.idName() || 'id';
    verifyOptions.redirect = verifyOptions.redirect || '/';
    const defaultTemplate = path.join(__dirname, '..', 'templates', 'verifyPhone.ejs');
    verifyOptions.template = path.resolve(verifyOptions.template || defaultTemplate);
    verifyOptions.phoneNumber = phoneNumber;
    verifyOptions.protocol = verifyOptions.protocol || 'http';

    const app = phoneNumberModel.app;
    verifyOptions.host = verifyOptions.host || (app && app.get('host')) || 'localhost';
    verifyOptions.port = verifyOptions.port || (app && app.get('port')) || 3000;
    verifyOptions.restApiRoot = verifyOptions.restApiRoot || (app && app.get('restApiRoot')) || '/api';

    const displayPort = (
      (verifyOptions.protocol === 'http' && verifyOptions.port == '80') ||
      (verifyOptions.protocol === 'https' && verifyOptions.port == '443')
    ) ? '' : ':' + verifyOptions.port;

    const urlPath = joinUrlPath(
      verifyOptions.restApiRoot,
      phoneNumberModel.http.path,
      phoneNumberModel.sharedClass.findMethodByName('confirm').http.path
    );

    verifyOptions.to = phoneNumber.phone;
    verifyOptions.subject = verifyOptions.subject || g.f('Thanks for Registering');
    verifyOptions.headers = verifyOptions.headers || {};

    // assert the verifyOptions params that might have been badly defined
    assertVerifyOptions(verifyOptions);

    // argument "options" is passed depending on verifyOptions.generateVerificationToken function requirements
    const tokenGenerator = verifyOptions.generateVerificationToken;
    if (tokenGenerator.length == 3) {
      tokenGenerator(phoneNumber, options, addTokenToUserAndSave);
    } else {
      tokenGenerator(phoneNumber, addTokenToUserAndSave);
    }

    function addTokenToUserAndSave(err, secret) {
      if (err) return cb(err);
      const token = speakeasy.totp({
        secret: secret,
        encoding: 'base32',
        step: 10 * 60,
      });
      user.phones.updateById(phoneNumber.id, {
        verificationToken: secret,
      }, function(err, newPhoneNumber) {
        if (err) return cb(err);
        phoneNumber = newPhoneNumber;
        sendPhone(token, phoneNumber);
      });
    }

    // TODO - support more verification types
    function sendPhone(token, phoneNumber) {
      verifyOptions.verificationToken = token;

      // argument "options" is passed depending on templateFn function requirements
      const templateFn = verifyOptions.templateFn;
      if (templateFn.length == 3) {
        templateFn(verifyOptions, options, setContentAndSend);
      } else {
        templateFn(verifyOptions, setContentAndSend);
      }

      function setContentAndSend(err, text) {
        if (err) return cb(err);

        verifyOptions.text = text;

        // Remove verifyOptions.template to prevent rejection by certain
        // nodphoneer transport plugins.
        delete verifyOptions.template;

        // argument "options" is passed depending on Email.send function requirements
        const Email = verifyOptions.phoner;
        if (Email.send.length == 3) {
          Email.send(verifyOptions, options, handleAfterSend);
        } else {
          Email.send(verifyOptions, handleAfterSend);
        }

        function handleAfterSend(err, phone) {
          if (err) return cb(err);
          cb(null, {phone: phone, token: token, uid: user[userModel.definition.idName() || 'id']});
        }
      }
    }

    return cb.promise;
  };

  function assertVerifyOptions(verifyOptions) {
    assert(verifyOptions.type, 'You must supply a verification type (verifyOptions.type)');
    assert(verifyOptions.type === 'phone', 'Unsupported verification type');
    assert(verifyOptions.to, 'Must include verifyOptions.to when calling phoneNumber.verify() ' +
      'or the phoneNumber must have an phone property');
    assert(verifyOptions.from, 'Must include verifyOptions.from when calling phoneNumber.verify()');
    assert(typeof verifyOptions.templateFn === 'function',
      'templateFn must be a function');
    assert(typeof verifyOptions.generateVerificationToken === 'function',
      'generateVerificationToken must be a function');
    assert(verifyOptions.phoner, 'A phoner function must be provided');
    assert(typeof verifyOptions.phoner.send === 'function', 'phoner.send must be a function ');
  }

  function createVerificationEmailBody(verifyOptions, options, cb) {
    const template = loopback.template(verifyOptions.template);
    const body = template(verifyOptions);
    cb(null, body);
  }

  /**
   * A default verification token generator which accepts the phoneNumber the token is
   * being generated for and a callback function to indicate completion.
   * This one uses the crypto library and 64 random bytes (converted to hex)
   * for the token. When used in combination with the phoneNumber.verify() method this
   * function will be called with the `phoneNumber` object as it's context (`this`).
   *
   * @param {object} phoneNumber The PhoneNumber this token is being generated for.
   * @param {Function} cb The generator must pass back the new token with this function call
   */
  PhoneNumber.generateVerificationToken = function(phoneNumber, cb) {
    cb(null, speakeasy.generateSecret().base32);
  };

  PhoneNumber.setup = function() {
    const PhoneNumberModel = this;

    PhoneNumberModel.setter.phone = function(value) {
      const ph = phone(value);
      this.$phone = ph[0];
      this.$country = ph[1];
    };

    PhoneNumberModel.setter.masked = function(value) {
      this.$masked = value.slice(0, 4) + value.slice(4, value.length).replace(/\d(?=\d{3})/g, '*');
    };

    // Make sure verified is not set by creation
    PhoneNumberModel.beforeRemote('create', function(ctx, user, next) {
      const body = ctx.req.body;
      if (body && body.verified) {
        body.verified = false;
      }
      next();
    });

    PhoneNumberModel.remoteMethod(
      'confirm',
      {
        description: 'Confirm a phoneNumber registration with verification token.',
        accepts: [
          {arg: 'pId', type: 'string', required: true},
          {arg: 'token', type: 'string', required: true},
          {arg: 'redirect', type: 'string'},
        ],
        http: {verb: 'get', path: '/confirm'},
      }
    );

    PhoneNumberModel.validate('phone', phoneValidator, {
      message: g.f('Must provide a valid phone'),
    });

    return PhoneNumberModel;
  };

  /*!
   * Setup the base phoneNumber.
   */

  PhoneNumber.setup();

  PhoneNumber.observe('before save', function(ctx, next) {
    if (ctx.isNewInstance) {
      ctx.instance.masked = ctx.instance.phone;
    } else {
      const isPartialUpdateChangingPhone = ctx.data && 'phone' in ctx.data;
      const isFullReplaceChangingPhone = !!ctx.instance;

      if (isPartialUpdateChangingPhone || isFullReplaceChangingPhone) {
        if (ctx.instance) {
          ctx.instance.masked = ctx.instance.phone;
          if (ctx.Model.settings.verificationRequired) {
            ctx.instance.verified = false;
          }
        } else {
          if (ctx.Model.settings.verificationRequired) {
            ctx.data.verified = false;
          }
        }
      }
    }
    next();
  });
};

// TODO: proper phone number validator
function phoneValidator(err) {
  const value = this.phone;
  if (value == null)
    return;
  if (typeof value !== 'string')
    return err('string');
  if (value === '') return;
  if (!phone(value).length)
    return err('phone');
}

function joinUrlPath(args) {
  let result = arguments[0];
  for (let ix = 1; ix < arguments.length; ix++) {
    const next = arguments[ix];
    result += result[result.length - 1] === '/' && next[0] === '/' ?
      next.slice(1) : next;
  }
  return result;
}
