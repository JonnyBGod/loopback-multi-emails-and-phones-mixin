'use strict';
var isEmail = require('isemail');
var loopback = require('loopback/lib/loopback');
var g = require('strong-globalize')();
var speakeasy = require('speakeasy');
var utils = require('loopback/lib/utils');
var assert = require('assert');
var path = require('path');
var qs = require('querystring');

var debug = require('debug')('core:emailAddress');

module.exports = function(EmailAddress) {
  /**
   * Verify a user's identity by sending them a confirmation message.
   * NOTE: Currently only email verification is supported
   *
   * ```js
   * var verifyOptions = {
   *   type: 'email',
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
   * @property {String} type Must be `'email'` in the current implementation.
   * @property {Function} mailer A mailer function with a static `.send() method.
   *  The `.send()` method must accept the verifyOptions object, the method's
   *  remoting context options object and a callback function with `(err, email)`
   *  as parameters.
   *  Defaults to provided `userModel.email` function, or ultimately to LoopBack's
   *  own mailer function.
   * @property {String} to Email address to which verification email is sent.
   *  Defaults to user's email. Can also be overriden to a static value for test
   *  purposes.
   * @property {String} from Sender email address
   *  For example `'noreply@example.com'`.
   * @property {String} subject Subject line text.
   *  Defaults to `'Thanks for Registering'` or a local equivalent.
   * @property {String} text Text of email.
   *  Defaults to `'Please verify your email by opening this link in a web browser:`
   *  followed by the verify link.
   * @property {Object} headers Email headers. None provided by default.
   * @property {String} template Relative path of template that displays verification
   *  page. Defaults to `'../../templates/verify.ejs'`.
   * @property {Function} templateFn A function generating the email HTML body
   *  from `verify()` options object and generated attributes like `options.verifyHref`.
   *  It must accept the verifyOptions object, the method's remoting context options
   *  object and a callback function with `(err, html)` as parameters.
   *  A default templateFn function is provided, see `createVerificationEmailBody()`
   *  for implementation details.
   * @property {String} redirect Page to which user will be redirected after
   *  they verify their email. Defaults to `'/'`.
   * @property {String} verifyHref The link to include in the user's verify message.
   *  Defaults to an url analog to:
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
   *  execute the callback with the token! User saving and email sending will be
   *  handled in the `verify()` method.
   *  A default token generation function is provided, see `generateVerificationToken()`
   *  for implementation details.
   * @callback {Function} cb Callback function.
   * @param {Object} options remote context options.
   * @param {Error} err Error object.
   * @param {Object} object Contains email, token, uid.
   * @promise
   */

  EmailAddress.prototype.verify = function(user, verifyOptions, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    var emailAddress = this;
    var emailAddressModel = this.constructor;
    var userModel = user.constructor;
    var registry = emailAddressModel.registry;
    verifyOptions = Object.assign({}, verifyOptions);
    // final assertion is performed once all options are assigned
    assert(typeof verifyOptions === 'object',
      'verifyOptions object param required when calling emailAddress.verify()');

    // Shallow-clone the options object so that we don't override
    // the global default options object
    verifyOptions = Object.assign({}, verifyOptions);

    // Set a default template generation function if none provided
    verifyOptions.templateFn = verifyOptions.templateFn || createVerificationEmailBody;

    // Set a default token generation function if none provided
    verifyOptions.generateVerificationToken = verifyOptions.generateVerificationToken ||
      EmailAddress.generateVerificationToken;

    // Set a default mailer function if none provided
    verifyOptions.mailer = verifyOptions.mailer || EmailAddress.email ||
      registry.getModelByType(loopback.Email);

    var pkName = emailAddressModel.definition.idName() || 'id';
    verifyOptions.redirect = verifyOptions.redirect || '/';
    var defaultTemplate = path.join(__dirname, '..', 'templates', 'verifyEmail.ejs');
    verifyOptions.template = path.resolve(verifyOptions.template || defaultTemplate);
    verifyOptions.emailAddress = emailAddress;
    verifyOptions.protocol = verifyOptions.protocol || 'http';

    var app = emailAddressModel.app;
    verifyOptions.host = verifyOptions.host || (app && app.get('host')) || 'localhost';
    verifyOptions.port = verifyOptions.port || (app && app.get('port')) || 3000;
    verifyOptions.restApiRoot = verifyOptions.restApiRoot || (app && app.get('restApiRoot')) || '/api';

    var displayPort = (
      (verifyOptions.protocol === 'http' && verifyOptions.port == '80') ||
      (verifyOptions.protocol === 'https' && verifyOptions.port == '443')
    ) ? '' : ':' + verifyOptions.port;

    var urlPath = joinUrlPath(
      verifyOptions.restApiRoot,
      userModel.http.path,
      userModel.sharedClass.findMethodByName('confirm').http.path
    );

    verifyOptions.verifyHref = verifyOptions.verifyHref ||
      verifyOptions.protocol +
      '://' +
      verifyOptions.host +
      displayPort +
      urlPath +
      '?' + qs.stringify({
          uid: '' + verifyOptions.emailAddress[pkName],
          redirect: verifyOptions.redirect,
        });

    verifyOptions.to = emailAddress.email;
    verifyOptions.subject = verifyOptions.subject || g.f('Thanks for Registering');
    verifyOptions.headers = verifyOptions.headers || {};

    // assert the verifyOptions params that might have been badly defined
    assertVerifyOptions(verifyOptions);

    // argument "options" is passed depending on verifyOptions.generateVerificationToken function requirements
    var tokenGenerator = verifyOptions.generateVerificationToken;
    if (tokenGenerator.length == 3) {
      tokenGenerator(emailAddress, options, addTokenToUserAndSave);
    } else {
      tokenGenerator(emailAddress, addTokenToUserAndSave);
    }

    function addTokenToUserAndSave(err, secret) {
      if (err) return cb(err);
      var token = speakeasy.totp({
        secret: secret,
        encoding: 'base32',
        step: 30 * 60,
      });

      user.emails.updateById(emailAddress.id, {
        verificationToken: secret,
      }, function(err, newEmailAddress) {
        if (err) return cb(err);
        emailAddress = newEmailAddress;
        sendEmail(token, emailAddress);
      });
    }

    // TODO - support more verification types
    function sendEmail(token, emailAddress) {
      verifyOptions.verifyHref += '&token=' + token;
      verifyOptions.verificationToken = token;
      verifyOptions.text = verifyOptions.text || g.f('Please verify your email by opening ' +
        'this link in a web browser:\n\t%s', verifyOptions.verifyHref);
      verifyOptions.text = verifyOptions.text.replace(/\{href\}/g, verifyOptions.verifyHref);

      // argument "options" is passed depending on templateFn function requirements
      var templateFn = verifyOptions.templateFn;
      if (templateFn.length == 3) {
        templateFn(verifyOptions, options, setHtmlContentAndSend);
      } else {
        templateFn(verifyOptions, setHtmlContentAndSend);
      }

      function setHtmlContentAndSend(err, html) {
        if (err) return cb(err);

        verifyOptions.html = html;

        // Remove verifyOptions.template to prevent rejection by certain
        // nodemailer transport plugins.
        delete verifyOptions.template;

        // argument "options" is passed depending on Email.send function requirements
        var Email = verifyOptions.mailer;
        if (Email.send.length == 3) {
          Email.send(verifyOptions, options, handleAfterSend);
        } else {
          Email.send(verifyOptions, handleAfterSend);
        }

        function handleAfterSend(err, email) {
          if (err) return cb(err);
          cb(null, {email: email, token: token, uid: user[userModel.definition.idName() || 'id']});
        }
      }
    }

    return cb.promise;
  };

  function assertVerifyOptions(verifyOptions) {
    assert(verifyOptions.type, 'You must supply a verification type (verifyOptions.type)');
    assert(verifyOptions.type === 'email', 'Unsupported verification type');
    assert(verifyOptions.to, 'Must include verifyOptions.to when calling emailAddress.verify() ' +
      'or the emailAddress must have an email property');
    assert(verifyOptions.from,
      'Must include verifyOptions.from when calling emailAddress.verify()');
    assert(typeof verifyOptions.templateFn === 'function',
      'templateFn must be a function');
    assert(typeof verifyOptions.generateVerificationToken === 'function',
      'generateVerificationToken must be a function');
    assert(verifyOptions.mailer, 'A mailer function must be provided');
    assert(typeof verifyOptions.mailer.send === 'function', 'mailer.send must be a function ');
  }

  function createVerificationEmailBody(verifyOptions, options, cb) {
    var template = loopback.template(verifyOptions.template);
    var body = template(verifyOptions);
    cb(null, body);
  }

  /**
   * A default verification token generator which accepts the phoneNumber the token is
   * being generated for and a callback function to indicate completion.
   * This one uses the crypto library and 64 random bytes (converted to hex)
   * for the token. When used in combination with the phoneNumber.verify() method this
   * function will be called with the `phoneNumber` object as it's context (`this`).
   *
   * @param {object} phoneNumber The EmailAddress this token is being generated for.
   * @param {Function} cb The generator must pass back the new token with this function call
   */
  EmailAddress.generateVerificationToken = function(phoneNumber, cb) {
    cb(null, speakeasy.generateSecret().base32);
  };

  EmailAddress.setup = function() {
    var EmailAddressModel = this;

    EmailAddressModel.setter.email = function(value) {
      if (!EmailAddressModel.settings.caseSensitiveEmail) {
        this.$email = value.toLowerCase();
      } else {
        this.$email = value;
      }
    };

    EmailAddressModel.setter.masked = function(value) {
      this.$masked = value.replace(/(?!^).(?=[^@]+@)/g, '*');
    };

    // Make sure verified is not set by creation
    EmailAddressModel.beforeRemote('create', function(ctx, user, next) {
      var body = ctx.req.body;
      if (body && body.verified) {
        body.verified = false;
      }
      next();
    });

    EmailAddressModel.remoteMethod(
      'confirm',
      {
        description: 'Confirm a emailAddress registration with verification token.',
        accepts: [
          {arg: 'eid', type: 'string', required: true},
          {arg: 'token', type: 'string', required: true},
          {arg: 'redirect', type: 'string'},
        ],
        http: {verb: 'get', path: '/confirm'},
      }
    );

    EmailAddressModel.validate('email', emailValidator, {
      message: g.f('Must provide a valid email'),
    });

    return EmailAddressModel;
  };

  /*!
   * Setup the base emailAddress.
   */

  EmailAddress.setup();

  EmailAddress.observe('access', function normalizeEmailCase(ctx, next) {
    if (!ctx.Model.settings.caseSensitiveEmail && ctx.query.where &&
        ctx.query.where.email && typeof(ctx.query.where.email) === 'string') {
      ctx.query.where.email = ctx.query.where.email.toLowerCase();
    }
    next();
  });

  EmailAddress.observe('before save', function(ctx, next) {
    if (ctx.isNewInstance) {
      ctx.instance.masked = ctx.instance.email;
    } else {
      var isPartialUpdateChangingEmail = ctx.data && 'email' in ctx.data;
      var isFullReplaceChangingEmail = !!ctx.instance;

      if (isPartialUpdateChangingEmail || isFullReplaceChangingEmail) {
        if (ctx.instance) {
          ctx.instance.masked = ctx.instance.email;
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

function emailValidator(err) {
  var value = this.email;
  if (value == null)
    return;
  if (typeof value !== 'string')
    return err('string');
  if (value === '') return;
  if (!isEmail.validate(value))
    return err('email');
}

function joinUrlPath(args) {
  var result = arguments[0];
  for (var ix = 1; ix < arguments.length; ix++) {
    var next = arguments[ix];
    result += result[result.length - 1] === '/' && next[0] === '/' ?
      next.slice(1) : next;
  }
  return result;
}
