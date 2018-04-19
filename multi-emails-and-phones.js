'use strict';
var isEmail = require('isemail');
var phone = require('phone');
var async = require('async');
var g = require('strong-globalize')();
var loopback = require('loopback/lib/loopback');
var utils = require('loopback/lib/utils');
var path = require('path');
var speakeasy = require('speakeasy');

var DEFAULT_RESET_PW_TTL = 15 * 60; // 15 mins in seconds
var assert = require('assert');

var debug = require('debug')('loopback:user');

module.exports = function(User, options) {
  delete User.validations.email;

  var Phone = User.registry.createModel(require('./models/phone.json'));
  require('./models/phone.js')(Phone);

  var emailAddressSchema = require('./models/emailAddress.json');
  if (options.showEmail) {
    emailAddressSchema.hidden.splice(emailAddressSchema.hidden.indexOf('email'), 1);
  }

  var EmailAddress = User.registry.createModel(emailAddressSchema);
  require('./models/emailAddress.js')(EmailAddress);
  User.registry.configureModel(EmailAddress, {
    dataSource: User.getDataSource(),
  });
  EmailAddress.email = User.email;

  User.embedsMany(EmailAddress, {as: 'emails', options: {persistent: true, validate: false}});

  var PhoneNumber = User.registry.createModel(require('./models/phoneNumber.json'));
  require('./models/phoneNumber.js')(PhoneNumber);
  User.registry.configureModel(PhoneNumber, {
    dataSource: User.getDataSource(),
  });

  User.embedsMany(PhoneNumber, {as: 'phones', options: {persistent: true, validate: false}});

  User.setCaseSensitiveEmail = function(value) {
    this.settings.caseSensitiveEmail = value;
    this.relations.emails.modelTo.settings.caseSensitiveEmail = value;
  };

  User.setVerificationRequired = function(value) {
    this.settings.emailVerificationRequired = value;
    this.relations.emails.modelTo.settings.verificationRequired = value;
    this.relations.phones.modelTo.settings.verificationRequired = value;
  };

  function splitPrincipal(name, realmDelimiter) {
    var parts = [null, name];
    if (!realmDelimiter) {
      return parts;
    }
    var index = name.indexOf(realmDelimiter);
    if (index !== -1) {
      parts[0] = name.substring(0, index);
      parts[1] = name.substring(index + realmDelimiter.length);
    }
    return parts;
  }

  /**
   * Normalize the credentials
   * @param {Object} credentials The credential object
   * @param {Boolean} realmRequired
   * @param {String} realmDelimiter The realm delimiter, if not set, no realm is needed
   * @returns {Object} The normalized credential object
   */
  User.normalizeCredentials = function(credentials, realmRequired, realmDelimiter) {
    var query = {};
    credentials = credentials || {};
    if (!realmRequired) {
      if (credentials.email) {
        query.email = credentials.email;
      } else if (credentials.phone) {
        query.phone = credentials.phone;
      } else if (credentials.username) {
        query.username = credentials.username;
      }
    } else {
      if (credentials.realm) {
        query.realm = credentials.realm;
      }
      var parts;
      if (credentials.email) {
        parts = splitPrincipal(credentials.email, realmDelimiter);
        query.email = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      } else if (credentials.phone) {
        parts = splitPrincipal(credentials.phone, realmDelimiter);
        query.phone = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      } else if (credentials.username) {
        parts = splitPrincipal(credentials.username, realmDelimiter);
        query.username = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      }
    }
    return query;
  };

  /**
   * Login a user by with the given `credentials`.
   *
   * ```js
   *    User.login({username: 'foo', password: 'bar'}, function (err, token) {
  *      console.log(token.id);
  *    });
   * ```
   *
   * @param {Object} credentials username/password or email/password
   * @param {String[]|String} [include] Optionally set it to "user" to include
   * the user info
   * @callback {Function} callback Callback function
   * @param {Error} err Error object
   * @param {AccessToken} token Access token if login is successful
   * @promise
   */

  User.login = function(credentials, include, fn) {
    var self = this;
    var includeRelations, realmDelimiter;

    if (typeof include === 'function') {
      fn = include;
      include = undefined;
    }

    fn = fn || utils.createPromiseCallback();

    include = (include || '');
    if (Array.isArray(include)) {
      includeRelations = include.filter(function(val) {
        return val.indexOf('user.') !== -1;
      });

      if (includeRelations && includeRelations.length) {
        include = include.filter(function(val) {
          return val.indexOf('user.') === -1;
        });

        includeRelations = includeRelations.map(function(val) {
          return val.replace('user.', '');
        });
      }

      include = include.map(function(val) {
        return val.toLowerCase();
      });
    } else {
      include = include.toLowerCase();
    }

    // Check if realm is required
    var realmRequired = !!(self.settings.realmRequired ||
      self.settings.realmDelimiter);
    if (realmRequired) {
      realmDelimiter = self.settings.realmDelimiter;
    }
    var query = self.normalizeCredentials(credentials, realmRequired,
      realmDelimiter);

    if (realmRequired && !query.realm) {
      var err1 = new Error(g.f('{{realm}} is required'));
      err1.statusCode = 400;
      err1.code = 'REALM_REQUIRED';
      fn(err1);
      return fn.promise;
    }
    if (!query.email && !query.username && !query.phone) {
      var err2 = new Error(g.f('{{username}}, {{email}} or {{phone}} is required'));
      err2.statusCode = 400;
      err2.code = 'USERNAME_EMAIL_PHONE_REQUIRED';
      fn(err2);
      return fn.promise;
    }

    if (query.email) {
      query['emailAddresses.email'] = query.email;
      delete query.email;
    } else if (query.phone) {
      query['phoneNumbers.phone'] = phone(query.phone)[0];
      delete query.phone;
    }

    self.findOne({where: query, include: includeRelations}, function(err, user) {
      function defaultError() {
        var defError = new Error(g.f('login failed'));
        defError.statusCode = 401;
        defError.code = 'LOGIN_FAILED';

        return defError;
      }

      function tokenHandler(err, token) {
        if (err) return fn(err);
        if (Array.isArray(include) ? include.indexOf('user') !== -1 : include === 'user') {
          // NOTE(bajtos) We can't set token.user here:
          //  1. token.user already exists, it's a function injected by
          //     "AccessToken belongsTo User" relation
          //  2. ModelBaseClass.toJSON() ignores own properties, thus
          //     the value won't be included in the HTTP response
          // See also loopback#161 and loopback#162
          token.__data.user = user;
        }
        fn(err, token);
      }

      if (err) {
        debug('An error is reported from User.findOne: %j', err);
        fn(defaultError());
      } else if (user) {
        user.hasPassword(credentials.password, function(err, isMatch) {
          if (err) {
            debug('An error is reported from User.hasPassword: %j', err);
            fn(defaultError());
          } else if (isMatch) {
            if (self.settings.emailVerificationRequired && query['emailAddresses.email'] &&
              !user.emailAddresses.filter(function(e) {
                return e.email === query['emailAddresses.email'];
              })[0].verified) {
              // Fail to log in if email verification is not done yet
              debug('User email has not been verified');
              err = new Error(g.f('login failed as the email has not been verified'));
              err.statusCode = 401;
              err.code = 'LOGIN_FAILED_EMAIL_NOT_VERIFIED';
              err.details = {
                userId: user.id,
              };
              fn(err);
            } else if (self.settings.emailVerificationRequired && query['phoneNumbers.phone'] &&
              !user.phoneNumbers.filter(function(e) {
                return e.phone === phone(query['phoneNumbers.phone'])[0];
              })[0].verified) {
              // Fail to log in if phone verification is not done yet
              debug('User phone has not been verified');
              err = new Error(g.f('login failed as the phone has not been verified'));
              err.statusCode = 401;
              err.code = 'LOGIN_FAILED_PHONE_NOT_VERIFIED';
              err.details = {
                userId: user.id,
              };
              fn(err);
            } else {
              if (user.createAccessToken.length === 2) {
                user.createAccessToken(credentials.ttl, tokenHandler);
              } else {
                user.createAccessToken(credentials.ttl, credentials, tokenHandler);
              }
            }
          } else {
            debug('The password is invalid for user %s', query.email || query.username);
            fn(defaultError());
          }
        });
      } else {
        debug('No matching record is found for user %s', query.email || query.username);
        fn(defaultError());
      }
    });

    return fn.promise;
  };

  /**
   * Verify a user's identity by sending them a confirmation message.
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
   * @property {Function} phoner A phoner function with a static `.send() method.
   *  The `.send()` method must accept the verifyOptions object, the method's
   *  remoting context options object and a callback function with `(err, email)`
   *  as parameters.
   *  Defaults to provided `userModel.email` function, or ultimately to LoopBack's
   *  own phoner function.
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

  User.prototype.verify = function(verifyOptions, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    var user = this;

    if (!verifyOptions.to) {
      var targets = [...user.emailAddresses, ...user.phoneNumbers];
      var target = targets.filter((t) => !t.verified)[0];
      if (target) {
        verifyOptions.to = target.id;
        verifyOptions.type = target.email ? 'email' : 'phone';
      }
    }
    // assert the verifyOptions params that might have been badly defined
    assertVerifyOptions(verifyOptions);

    if (verifyOptions.type === 'email') {
      user.emails.findOne({
        where: {or: [
          {id: verifyOptions.to},
          {email: verifyOptions.to},
        ]},
      }, function(err, email) {
        if (err) return cb(err);
        if (!email) {
          err = new Error(g.f('No email was found'));
          err.statusCode = 404;
          err.code = 'NO_EMAIL_FOUND';
          return cb(err);
        }
        email.verify(user, verifyOptions, options, cb);
      });
    } else if (verifyOptions.type === 'phone') {
      user.phones.findOne({
        where: {or: [
          {id: verifyOptions.to},
          {phone: phone(verifyOptions.to)[0]},
        ]},
      }, function(err, phone) {
        if (err) return cb(err);
        if (!phone) {
          err = new Error(g.f('No phone was found'));
          err.statusCode = 404;
          err.code = 'NO_PHONE_FOUND';
          return cb(err);
        }
        verifyOptions.to = phone.phone;
        phone.verify(user, verifyOptions, options, cb);
      });
    }

    return cb.promise;
  };

  function assertVerifyOptions(verifyOptions) {
    assert(verifyOptions.type, 'You must supply a verification type (verifyOptions.type)');
    assert(
      verifyOptions.type === 'email' || verifyOptions.type === 'phone',
      'Unsupported verification type'
    );
    assert(verifyOptions.to, 'You must supply verifyOptions.to');
  }

  /**
   * Confirm the user's identity.
   *
   * @param {Any} userId
   * @param {String} token The validation token
   * @param {String} redirect URL to redirect the user to once confirmed
   * @callback {Function} callback
   * @param {Error} err
   * @promise
   */
  User.confirm = function(uid, token, redirect, fn) {
    fn = fn || utils.createPromiseCallback();
    this.findById(uid, function(err, user) {
      if (err) {
        fn(err);
      } else {
        if (user) {
          var possibleTargets = [...user.emailAddresses, ...user.phoneNumbers];
          var target = null;

          for (var i = 0; i < possibleTargets.length; i++) {
            var verified = speakeasy.totp.verify({
              secret: possibleTargets[i].verificationToken,
              encoding: 'base32',
              token: token,
              step: (possibleTargets[i] instanceof EmailAddress ? 30 : 10) * 60,
            });
            if (verified) {
              target = possibleTargets[i];
              break;
            }
          }

          if (target) {
            user[target.email ? 'emails' : 'phones'].updateById(target.id, {
              verificationToken: null,
              verified: true,
            }, function(err) {
              if (err) {
                fn(err);
              } else {
                fn();
              }
            });
          } else {
            err = new Error(g.f('Invalid token: %s', token));
            err.statusCode = 400;
            err.code = 'INVALID_TOKEN';
            fn(err);
          }
        } else {
          err = new Error(g.f('User not found: %s', uid));
          err.statusCode = 404;
          err.code = 'USER_NOT_FOUND';
          fn(err);
        }
      }
    });
    return fn.promise;
  };

  /**
   * Create a short lived acess token for temporary login. Allows users
   * to change passwords if forgotten.
   *
   * @options {Object} options
   * @prop {String} email The user's email address
   * @callback {Function} callback
   * @param {Error} err
   * @promise
   */

  User.resetPassword = function(options, cb) {
    cb = cb || utils.createPromiseCallback();
    var UserModel = this;
    var ttl = UserModel.settings.resetPasswordTokenTTL || DEFAULT_RESET_PW_TTL;
    options = options || {};
    if (typeof options.email !== 'string' && typeof options.phone !== 'string') {
      var err = new Error(g.f('Email is required'));
      err.statusCode = 404;
      err.code = 'EMAIL_OR_PHONE_REQUIRED';
      cb(err);
      return cb.promise;
    }

    try {
      if (options.password) {
        UserModel.validatePassword(options.password);
      }
    } catch (err) {
      return cb(err);
    }

    var query = {};
    if (options.email) {
      query['emailAddresses.email'] = options.email;
    } else if (options.phone) {
      options.phone = phone(options.phone)[0];
      query['phoneNumbers.phone'] = options.phone;
    }

    UserModel.findOne({where: query}, function(err, user) {
      if (err) {
        return cb(err);
      }
      if (!user) {
        err = new Error(g.f('Email not found'));
        err.statusCode = 404;
        err.code = 'EMAIL_NOT_FOUND';
        return cb(err);
      }

      // create a short lived access token for temp login to change password
      // TODO(ritch) - eventually this should only allow password change
      if (UserModel.settings.emailVerificationRequired && options.email &&
        !user.emailAddresses.filter(function(e) {
          return e.email === options.email;
        })[0].verified) {
        err = new Error(g.f('Email has not been verified'));
        err.statusCode = 401;
        err.code = 'RESET_FAILED_EMAIL_NOT_VERIFIED';
        return cb(err);
      }

      if (UserModel.settings.emailVerificationRequired && options.phone &&
        !user.phoneNumbers.filter(function(e) {
          return e.phone === options.phone;
        })[0].verified) {
        err = new Error(g.f('Phone has not been verified'));
        err.statusCode = 401;
        err.code = 'RESET_FAILED_PHONE_NOT_VERIFIED';
        return cb(err);
      }

      if (UserModel.settings.restrictResetPasswordTokenScope) {
        const tokenData = {
          ttl: ttl,
          scopes: ['reset-password'],
        };
        user.createAccessToken(tokenData, options, onTokenCreated);
      } else {
        // We need to preserve backwards-compatibility with
        // user-supplied implementations of "createAccessToken"
        // that may not support "options" argument (we have such
        // examples in our test suite).
        user.createAccessToken(ttl, onTokenCreated);
      }

      function onTokenCreated(err, accessToken) {
        if (err) {
          return cb(err);
        }
        cb();

        if (options.email) {
          UserModel.emit('resetPasswordRequest', {
            email: options.email,
            accessToken: accessToken,
            user: user,
            options: options,
          });
        } else if (options.phone) {
          UserModel.emit('resetPasswordRequest', {
            phone: options.phone,
            accessToken: accessToken,
            user: user,
            options: options,
          });
        }
      }
    });

    return cb.promise;
  };

  User.validateUniqueness = function(value, type, isNewRecord, realm, done) {
    var self = this;

    if (blank(value)) {
      return process.nextTick(done);
    }

    var cond = {where: {}};

    if (type === 'email') {
      if (!self.settings.caseSensitiveEmail) {
        cond.where['emailAddresses.email'] = value.toLowerCase();
      } else {
        cond.where['emailAddresses.email'] = value;
      }
    } else if (type === 'phone') {
      cond.where['phoneNumbers.phone'] = phone(value)[0];
    }

    if (self.settings.realmRequired && self.settings.realmDelimiter) {
      if (typeof realm !== 'undefined') {
        cond.where['realm'] = realm;
      }
    }

    self.find(cond, function(error, found) {
      if (error) {
        done(error);
      } else if (found.length > 1) {
        done(generateError());
      } else if (found.length === 1 && isNewRecord) {
        done(generateError());
      } else if (found.length === 1 && (
        !this.id || !found[0].id || found[0].id.toString() != this.id.toString()
      )) {
        done(generateError());
      } else {
        done(null);
      }
    }.bind(this));

    function generateError() {
      var err;
      if (type === 'email') {
        err = new Error(g.f('Email already exists'));
      } else {
        err = new Error(g.f('Phone already exists'));
      }

      err.name = 'ValidationError';
      err.statusCode = 422;
      err.details = {
        context: self.modelName,
        codes: {
          email: ['custom.email'],
        },
      };

      return err;
    }
  };

  User.prototype.setPrimaryEmail = function(fk, fn) {
    fn = fn || utils.createPromiseCallback();
    var self = this;

    var emailIds = this.emailAddresses.map(function(address) { return address.id; });

    self.constructor.relations.emails.modelTo.updateAll({
      id: {
        inq: emailIds,
      },
    }, {
      primary: false,
    }, function(err, info) {
      if (err) return fn(err);

      self.constructor.relations.emails.modelTo.updateAll({
        id: fk,
      }, {
        primary: true,
      }, fn);
    });

    return fn.promise;
  };

  User.prototype.setPrimaryPhone = function(fk, fn) {
    fn = fn || utils.createPromiseCallback();
    var self = this;

    var phoneIds = this.phoneNumbers.map(function(number) { return number.id; });

    self.constructor.relations.phones.modelTo.updateAll({
      id: {
        inq: phoneIds,
      },
    }, {
      primary: false,
    }, function(err, info) {
      if (err) return fn(err);

      self.constructor.relations.phones.modelTo.updateAll({
        id: fk,
      }, {
        primary: true,
      }, fn);
    });

    return fn.promise;
  };

  User.setupMixin = function() {
    this.defineProperty('email', {type: String, required: false});
    this.defineProperty('phone', {type: String, required: false});

    if (this.settings.hidden.indexOf('email') === -1) {
      this.settings.hidden.push('email');
    }
    if (this.settings.hidden.indexOf('phone') === -1) {
      this.settings.hidden.push('phone');
    }

    if (this.settings.base === 'User') {
      this.base.clearObservers('before delete');
      this.base.clearObservers('access');
      this.base.clearObservers('before save');
      this.base.clearObservers('after save');
    } else if (this.base.settings.base === 'User') {
      this.base.base.clearObservers('before delete');
      this.base.base.clearObservers('access');
      this.base.base.clearObservers('before save');
      this.base.base.clearObservers('after save');
    } else {
      throw new Error('Multi emails and phones mixin: did not found User base model!');
    }

    this.relations.emails.modelTo.settings.verificationRequired =
      this.settings.emailVerificationRequired;
    this.relations.emails.modelTo.settings.caseSensitiveEmail =
      this.settings.caseSensitiveEmail;

    this.relations.phones.modelTo.settings.verificationRequired =
      this.settings.emailVerificationRequired;

    this.remoteMethod('setPrimaryEmail', {
      isStatic: false,
      description: 'Set the primary email address',
      accessType: 'WRITE',
      accepts: [
        {
          arg: 'fk', type: 'any',
          description: 'Foreign key for emailAddress',
          required: true,
          http: {source: 'path'},
        },
      ],
      http: {verb: 'put', path: '/setPrimaryEmail/:fk'},
    });

    this.remoteMethod('setPrimaryPhone', {
      isStatic: false,
      description: 'Set the primary phone number',
      accessType: 'WRITE',
      accepts: [
        {
          arg: 'fk', type: 'any',
          description: 'Foreign key for phoneNumber',
          required: true,
          http: {source: 'path'},
        },
      ],
      http: {verb: 'put', path: '/setPrimaryPhone/:fk'},
    });
  };

  /*!
   * Setup the base user.
   */
  User.setupMixin();

  if (!User.helpers) User.helpers = {};

  // --- OPERATION HOOKS ---
  //
  // Important: Operation hooks are inherited by subclassed models,
  // therefore they must be registered outside of setup() function

  // Access token to normalize email credentials
  User.observe('access', function normalizeEmailCase(ctx, next) {
    if (ctx.query.where) {
      if (ctx.query.where.email) {
        ctx.query.where['emailAddresses.email'] = ctx.query.where.email;
        delete ctx.query.where.email;
      } else if (ctx.query.where.phone) {
        ctx.query.where['phoneNumbers.phone'] = ctx.query.where.phone;
        delete ctx.query.where.phone;
      }

      if (ctx.query.where.or) {
        for (let i = ctx.query.where.or.length - 1; i >= 0; i--) {
          if (ctx.query.where.or[i].email) {
            ctx.query.where.or.splice(i, 1, {
              'emailAddresses.email': ctx.query.where.or[i].email,
            });
          } else if (ctx.query.where.or[i].phone) {
            ctx.query.where.or.splice(i, 1, {
              'phoneNumbers.phone': ctx.query.where.or[i].phone,
            });
          }
        }
      }

      if (ctx.query.where.and) {
        for (let i = ctx.query.where.and.length - 1; i >= 0; i--) {
          if (ctx.query.where.and[i].email) {
            ctx.query.where.and.splice(i, 1, {
              'emailAddresses.email': ctx.query.where.and[i].email,
            });
          } else if (ctx.query.where.and[i].phone) {
            ctx.query.where.and.splice(i, 1, {
              'phoneNumbers.phone': ctx.query.where.and[i].phone,
            });
          }
        }
      }

      if (!ctx.Model.settings.caseSensitiveEmail &&
        ctx.query.where['emailAddresses.email'] &&
        typeof(ctx.query.where['emailAddresses.email']) === 'string') {
        ctx.query.where['emailAddresses.email'] =
          ctx.query.where['emailAddresses.email'].toLowerCase();
      }
    }
    next();
  });

  User.helpers.normalizeEmailCase = function(ctx, next) {
    next();
  };

  User.observe('before save', function rejectInsecurePasswordChange(ctx, next) {
    const UserModel = ctx.Model;
    if (!UserModel.settings.rejectPasswordChangesViaPatchOrReplace) {
      // In legacy password flow, any DAO method can change the password
      return next();
    }

    if (ctx.isNewInstance) {
      // The password can be always set when creating a new User instance
      return next();
    }
    const data = ctx.data || ctx.instance;
    const isPasswordChange = 'password' in data;

    // This is the option set by `setPassword()` API
    // when calling `this.patchAttritubes()` to change user's password
    if (ctx.options.setPassword) {
      // Verify that only the password is changed and nothing more or less.
      if (Object.keys(data).length > 1 || !isPasswordChange) {
        // This is a programmer's error, use the default status code 500
        return next(new Error(
          'Invalid use of "options.setPassword". Only "password" can be ' +
          'changed when using this option.'));
      }

      return next();
    }

    if (!isPasswordChange) {
      return next();
    }

    const err = new Error(
      'Changing user password via patch/replace API is not allowed. ' +
      'Use changePassword() or setPassword() instead.');
    err.statusCode = 401;
    err.code = 'PASSWORD_CHANGE_NOT_ALLOWED';
    next(err);
  });

  User.helpers.beforeCreateEmbeded = function(ctx, next) {
    if (!ctx.isNewInstance || !ctx.instance) return next();

    if (ctx.isNewInstance) {
      var err;
      if (!ctx.instance.email && !ctx.instance.phone) {
        err = new Error(g.f('Must provide a valid email or phone'));
        err.name = 'ValidationError';
        err.statusCode = 422;
        err.details = {
          context: ctx.instance.constructor.modelName,
          codes: {
            email: ['presence'],
          },
        };
        return next(err);
      } else if (ctx.instance.email && !isEmail.validate(ctx.instance.email)) {
        err = new Error(g.f('Must provide a valid email'));
        err.name = 'ValidationError';
        err.statusCode = 422;
        err.details = {
          context: ctx.instance.constructor.modelName,
          codes: {
            email: ['custom.email'],
          },
        };
        return next(err);
      } else if (ctx.instance.phone && !phone(ctx.instance.phone).length) {
        err = new Error(g.f('Must provide a valid phone'));
        err.name = 'ValidationError';
        err.statusCode = 422;
        err.details = {
          context: ctx.instance.constructor.modelName,
          codes: {
            phone: ['custom.phone'],
          },
        };
        return next(err);
      }
    }

    if (ctx.instance.email || ctx.instance.phone) {
      async.parallel([
        function(callback) {
          if (!ctx.instance.email) return callback();

          ctx.instance.constructor.validateUniqueness(
            ctx.instance.email, 'email', ctx.isNewInstance, ctx.instance.realm,
            function(err) {
              ctx.hookState.email = ctx.instance.email;
              ctx.instance.unsetAttribute('email');

              callback(err);
            });
        },
        function(callback) {
          if (!ctx.instance.phone) return callback();

          ctx.instance.constructor.validateUniqueness(
            ctx.instance.phone, 'phone', ctx.isNewInstance, ctx.instance.realm,
            function(err) {
              ctx.hookState.phone = ctx.instance.phone;
              ctx.instance.unsetAttribute('phone');

              callback(err);
            });
        },
      ], next);
    } else {
      next();
    }
  };

  User.helpers.afterCreateEmbeded = function(ctx, next) {
    if (!ctx.instance) return next();
    if (!ctx.hookState.email && !ctx.hookState.phone) return next();

    async.parallel([
      function(callback) {
        if (!ctx.hookState.email) return callback();

        ctx.instance.emails.count({
          where: {
            primary: true,
          },
        }, function(err, nEmails) {
          var newEmail = {
            email: ctx.hookState.email,
          };
          if (nEmails < 1) {
            newEmail.primary = true;
          }
          ctx.instance.emails.create(newEmail, callback);
        });
      },
      function(callback) {
        if (!ctx.hookState.phone) return callback();

        ctx.instance.phones.count({
          where: {
            primary: true,
          },
        }, function(err, nPhones) {
          var newPhone = {
            phone: ctx.hookState.phone,
          };
          if (nPhones < 1) {
            newPhone.primary = true;
          }
          ctx.instance.phones.create(newPhone, callback);
        });
      },
    ], function(err, results) {
      next(err);
    });
  };

  // Create email and phone whem new User is created
  User.observe('before save', User.helpers.beforeCreateEmbeded);
  User.observe('after save', User.helpers.afterCreateEmbeded);

  // Delete old sessions once email is updated
  User.helpers.beforeEmailUpdate = function(ctx, next) {
    if (ctx.isNewInstance) return next();
    if (!ctx.where && !ctx.instance) return next();
    var where = ctx.where || {id: ctx.instance.id};

    var isPartialUpdateChangingPassword = ctx.data && 'password' in ctx.data;

    // Full replace of User instance => assume password change.
    // HashPassword returns a different value for each invocation,
    // therefore we cannot tell whether ctx.instance.password is the same
    // or not.
    var isFullReplaceChangingPassword = !!ctx.instance;

    ctx.hookState.isPasswordChange = isPartialUpdateChangingPassword ||
      isFullReplaceChangingPassword;

    ctx.Model.find({where: where}, ctx.options, function(err, userInstances) {
      if (err) return next(err);
      ctx.hookState.originalUserData = userInstances.map(function(u) {
        return {id: u.id, emailAddresses: u.emailAddresses, phoneNumbers: u.phoneNumbers};
      });

      next();
    });
  };

  User.helpers.afterEmailUpdate = function(ctx, next) {
    if (!ctx.instance && !ctx.data) return next();
    if (!ctx.hookState.originalUserData) return next();

    var newEmail = (ctx.instance || ctx.data).email;
    var newPhone = (ctx.instance || ctx.data).phone && phone((ctx.instance || ctx.data).phone)[0];
    var isPasswordChange = ctx.hookState.isPasswordChange;

    if (!newEmail && !newPhone && !isPasswordChange) return next();

    var userIdsToExpire = ctx.hookState.originalUserData.filter(function(u) {
      return (newEmail && !u.emailAddresses.filter(function(e) {
        return e.email === newEmail;
      }).length) || (newPhone && !u.phoneNumbers.filter(function(e) {
        return e.phone === newPhone;
      }).length) || isPasswordChange;
    }).map(function(u) {
      return u.id;
    });
    ctx.Model._invalidateAccessTokensOfUsers(userIdsToExpire, ctx.options, next);
  };

  User.observe('before save', User.helpers.beforeEmailUpdate);
  User.observe('after save', User.helpers.afterEmailUpdate);

  User.observe('before delete', function(ctx, next) {
    var AccessToken = ctx.Model.relations.accessTokens.modelTo;
    var EmailAddress = ctx.Model.relations.emails.modelTo;
    var PhoneNumber = ctx.Model.relations.phones.modelTo;
    var pkName = ctx.Model.definition.idName() || 'id';
    ctx.Model.find({where: ctx.where, fields: [pkName]}, function(err, list) {
      if (err) return next(err);

      var ids = list.map(function(u) { return u[pkName]; });
      ctx.where = {};
      ctx.where[pkName] = {inq: ids};

      EmailAddress.destroyAll({userId: {inq: ids}});
      PhoneNumber.destroyAll({userId: {inq: ids}});
      AccessToken.destroyAll({userId: {inq: ids}}, next);
    });
  });

  // Clean user related models
  User.observe('after delete', function(ctx, next) {
    var instanceId = ctx.instance && ctx.instance[ctx.Model.definition.idName() || 'id'];
    var whereId = ctx.where && ctx.where[ctx.Model.definition.idName() || 'id'];
    if (!(whereId || instanceId)) return next();

    ctx.Model._invalidateAccessTokensOfUsers([instanceId || whereId], ctx.options, next);
  });

  User.beforeRemote('prototype.__create__emails', function(ctx, user, next) {
    var body = ctx.req.body;
    if (body && body.verified) {
      body.verified = false;
    }

    ctx.instance.constructor.validateUniqueness(
      body.email, 'email', true, ctx.instance.realm,
      function(err) {
        next(err);
      });
  });

  User.beforeRemote('prototype.__create__phones', function(ctx, user, next) {
    var body = ctx.req.body;
    if (body && body.verified) {
      body.verified = false;
    }

    ctx.instance.constructor.validateUniqueness(
      body.phone, 'phone', true, ctx.instance.realm,
      function(err) {
        next(err);
      });
  });
};

function blank(v) {
  if (typeof v === 'undefined') return true;
  if (v instanceof Array && v.length === 0) return true;
  if (v === null) return true;
  if (typeof v === 'number' && isNaN(v)) return true;
  if (typeof v == 'string' && v === '') return true;
  return false;
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
