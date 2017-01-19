'use strict';
var isEmail = require('isemail');
var async = require('async');
var g = require('strong-globalize')();
var loopback = require('loopback/lib/loopback');
var utils = require('loopback/lib/utils');
var path = require('path');

var DEFAULT_RESET_PW_TTL = 15 * 60; // 15 mins in seconds
var assert = require('assert');

var debug = require('debug')('loopback:user');

module.exports = function(User) {
  delete User.validations.email;

  var Phone = User.registry.createModel(require('./models/phone.json'));
  require('./models/phone.js')(Phone);

  var EmailAddress = User.registry.createModel(require('./models/emailAddress.json'));
  require('./models/emailAddress.js')(EmailAddress);
  User.registry.configureModel(EmailAddress, {
    dataSource: User.getDataSource(),
  });

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
      query['phoneNumbers.phone'] = query.phone;
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
              fn(err);
            } else if (self.settings.emailVerificationRequired && query['phoneNumbers.phone'] &&
              !user.phoneNumbers.filter(function(e) {
                return e.phone === query['phoneNumbers.phone'];
              })[0].verified) {
              // Fail to log in if phone verification is not done yet
              debug('User phone has not been verified');
              err = new Error(g.f('login failed as the phone has not been verified'));
              err.statusCode = 401;
              err.code = 'LOGIN_FAILED_PHONE_NOT_VERIFIED';
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

  /**
   * Verify a user's identity by sending them a confirmation email.
   *
   * ```js
   *    var options = {
   *      type: 'email' | 'phone',
   *      to: user.email,
   *      template: 'verify.ejs',
   *      redirect: '/',
   *      tokenGenerator: function (user, cb) { cb("random-token"); }
   *    };
   *
   *    user.verify(options, next);
   * ```
   *
   * @options {Object} options
   * @property {String} type Must be 'email' or 'phone'.
   * @property {String} to Email address to which verification email is sent.
   * @property {String} from Sender email addresss, for example
   *   `'noreply@myapp.com'`.
   * @property {String} subject Subject line text.
   * @property {String} text Text of email.
   * @property {String} template Name of template that displays verification
   *  page, for example, `'verify.ejs'.
   * @property {Function} templateFn A function generating the email HTML body
   * from `verify()` options object and generated attributes like `options.verifyHref`.
   * It must accept the option object and a callback function with `(err, html)`
   * as parameters
   * @property {String} redirect Page to which user will be redirected after
   *  they verify their email, for example `'/'` for root URI.
   * @property {Function} generateVerificationToken A function to be used to
   *  generate the verification token. It must accept the user object and a
   *  callback function. This function should NOT add the token to the user
   *  object, instead simply execute the callback with the token! User saving
   *  and email sending will be handled in the `verify()` method.
   * @callback {Function} fn Callback function.
   * @param {Error} err Error object.
   * @param {Object} object Contains email, token, uid.
   * @promise
   */

  User.prototype.verify = function(options, fn) {
    fn = fn || utils.createPromiseCallback();

    var user = this;
    var userModel = this.constructor;
    var registry = userModel.registry;
    assert(typeof options === 'object', 'options required when calling user.verify()');
    assert(options.type, 'You must supply a verification type (options.type)');
    assert(options.type === 'email' || options.type === 'phone', 'Unsupported verification type');
    assert(options.to,
      'Must include options.to when calling user.verify()');
    assert(options.from, 'Must include options.from when calling user.verify()');

    options.redirect = options.redirect || '/';
    var defaultTemplate = path.join(__dirname, 'templates', 'verifyEmail.ejs');
    options.template = path.resolve(options.template || defaultTemplate);
    options.user = this;
    options.protocol = options.protocol || 'http';

    var app = userModel.app;
    options.host = options.host || (app && app.get('host')) || 'localhost';
    options.port = options.port || (app && app.get('port')) || 3000;
    options.restApiRoot = options.restApiRoot || (app && app.get('restApiRoot')) || '/api';

    var displayPort = (
      (options.protocol === 'http' && options.port == '80') ||
      (options.protocol === 'https' && options.port == '443')
    ) ? '' : ':' + options.port;

    options.urlPath = joinUrlPath(
      options.restApiRoot,
      userModel.http.path,
      userModel.sharedClass.findMethodByName('confirm').http.path
    );

    options.verifyHref = options.verifyHref ||
      options.protocol +
      '://' +
      options.host +
      displayPort +
      options.urlPath +
      '?uid=' +
      options.user.id +
      '&redirect=' +
      options.redirect;

    options.mailer = options.mailer ||
      this.constructor.email ||
      registry.getModelByType(loopback.Email);

    if (options.type === 'email') {
      user.emails.findOne({where: {email: options.to}}, function(err, email) {
        if (err) return fn(err);
        email.verify(options, fn);
      });
    } else if (options.type === 'phone') {
      user.phones.findOne({where: {phone: options.to}}, function(err, phone) {
        if (err) return fn(err);
        phone.verify(options, fn);
      });
    }

    return fn.promise;
  };

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
          user.emails.findOne({
            where: {
              verificationToken: token,
            },
          }, function(err, email) {
            if (err) {
              fn(err);
            } else {
              if (email) {
                email.verificationToken = null;
                email.verified = true;
                email.save(function(err) {
                  if (err) {
                    fn(err);
                  } else {
                    fn();
                  }
                });
              } else {
                user.phones.findOne({
                  where: {
                    verificationToken: token,
                  },
                }, function(err, phone) {
                  if (err) {
                    fn(err);
                  } else {
                    if (phone) {
                      phone.verificationToken = null;
                      phone.verified = true;
                      phone.save(function(err) {
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
                  }
                });
              }
            }
          });
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
    if (typeof options.email !== 'string') {
      var err = new Error(g.f('Email is required'));
      err.statusCode = 400;
      err.code = 'EMAIL_REQUIRED';
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

      user.createAccessToken(ttl, function(err, accessToken) {
        if (err) {
          return cb(err);
        }
        cb();

        if (options.email) {
          UserModel.emit('resetPasswordRequest', {
            email: options.email,
            accessToken: accessToken,
            user: user,
          });
        } else if (options.phone) {
          UserModel.emit('resetPasswordRequest', {
            phone: options.phone,
            accessToken: accessToken,
            user: user,
          });
        }
      });
    });

    return cb.promise;
  };

  User.validateUniqueness = function(value, type, isNewRecord, realm, done) {
    var UserModel = this;

    if (blank(value)) {
      return process.nextTick(done);
    }

    var cond = {where: {}};

    if (type === 'email') {
      if (!User.settings.caseSensitiveEmail) {
        cond.where['emailAddresses.email'] = value.toLowerCase();
      } else {
        cond.where['emailAddresses.email'] = value;
      }
    } else if (type === 'phone') {
      cond.where['phoneNumbers.phone'] = value;
    }

    if (UserModel.settings.realmRequired && UserModel.settings.realmDelimiter) {
      if (realm !== undefined)
        cond.where['realm'] = realm;
    }

    User.find(cond, function(error, found) {
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
      if (type === 'email') {
        var err = new Error(g.f('Email already exists'));
      } else {
        var err = new Error(g.f('Phone already exists'));
      }

      err.name = 'ValidationError';
      err.statusCode = 422;
      err.details = {
        context: UserModel.modelName,
        codes: {
          email: ['custom.email'],
        },
      };

      return err;
    }
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

    this.settings.realmRequired = this.settings.realmRequired || null;
    this.settings.realmDelimiter = this.settings.realmDelimiter || null;

    this.base.clearObservers('before delete');
    this.base.clearObservers('access');
    this.base.clearObservers('before save');
    this.base.clearObservers('after save');

    this.relations.emails.modelTo.settings.verificationRequired =
      this.settings.emailVerificationRequired;
    this.relations.emails.modelTo.settings.caseSensitiveEmail =
      this.settings.caseSensitiveEmail;

    this.relations.phones.modelTo.settings.verificationRequired =
      this.settings.emailVerificationRequired;
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
        for (var i = ctx.query.where.or.length - 1; i >= 0; i--) {
          if (ctx.query.where.or[i].email) {
            ctx.query.where.or.splice(i, 1, {'emailAddresses.email': ctx.query.where.or[i].email});
          } else if (ctx.query.where.or[i].phone) {
            ctx.query.where.or.splice(i, 1, {'phoneNumbers.phone': ctx.query.where.or[i].phone});
          }
        }
      }

      if (ctx.query.where.and) {
        for (var i = ctx.query.where.and.length - 1; i >= 0; i--) {
          if (ctx.query.where.and[i].email) {
            ctx.query.where.and.splice(i, 1, {'emailAddresses.email': ctx.query.where.and[i].email});
          } else if (ctx.query.where.and[i].phone) {
            ctx.query.where.and.splice(i, 1, {'phoneNumbers.phone': ctx.query.where.and[i].phone});
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

  User.helpers.beforeCreateEmbeded = function(ctx, next) {
    if (!ctx.isNewInstance || !ctx.instance) return next();

    if (ctx.isNewInstance) {
      if (!ctx.instance.email) {
        var err = new Error(g.f('Must provide a valid email'));
        err.name = 'ValidationError';
        err.statusCode = 422;
        err.details = {
          context: User.modelName,
          codes: {
            email: ['presence'],
          },
        };
        return next(err);
      } else if (!isEmail(ctx.instance.email)) {
        var err = new Error(g.f('Must provide a valid email'));
        err.name = 'ValidationError';
        err.statusCode = 422;
        err.details = {
          context: User.modelName,
          codes: {
            email: ['custom.email'],
          },
        };
        return next(err);
      }
    }

    if (ctx.instance.email || ctx.instance.phone) {
      var realm = ctx.instance.realm;

      async.parallel([
        function(callback) {
          if (!ctx.instance.email) return callback();

          User.validateUniqueness(ctx.instance.email, 'email', ctx.isNewInstance, realm,
          function(err) {
            ctx.hookState.email = ctx.instance.email;
            ctx.instance.unsetAttribute('email');

            callback(err);
          });
        },
        function(callback) {
          if (!ctx.instance.phone) return callback();

          User.validateUniqueness(ctx.instance.phone, 'phone', ctx.isNewInstance, realm,
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

    ctx.Model.find({where: where}, function(err, userInstances) {
      if (err) return next(err);
      ctx.hookState.originalUserData = userInstances.map(function(u) {
        return {id: u.id, emailAddresses: u.emailAddresses};
      });

      next();
    });
  };

  User.helpers.afterEmailUpdate = function(ctx, next) {
    if (!ctx.instance && !ctx.data) return next();
    if (!ctx.hookState.originalUserData) return next();

    var newEmail = (ctx.instance || ctx.data).email;
    var isPasswordChange = ctx.hookState.isPasswordChange;

    if (!newEmail && !isPasswordChange) return next();

    var userIdsToExpire = ctx.hookState.originalUserData.filter(function(u) {
      return (newEmail && u.emailAddresses.filter(function(e) {
        return e.email === newEmail;
      }).length === 0) || isPasswordChange;
    }).map(function(u) {
      return u.id;
    });
    ctx.Model._invalidateAccessTokensOfUsers(userIdsToExpire, next);
  };

  User.observe('before save', User.helpers.beforeEmailUpdate);
  User.observe('after save', User.helpers.afterEmailUpdate);

  // Clean user related models
  User.observe('after delete', function(ctx, next) {
    var instanceId = ctx.instance && ctx.instance[ctx.Model.definition.idName() || 'id'];
    var whereId = ctx.where && ctx.where[ctx.Model.definition.idName() || 'id'];
    if (!(whereId || instanceId)) return next();

    ctx.Model._invalidateAccessTokensOfUsers([instanceId || whereId], next);
  });

  User.beforeRemote('prototype.__create__emails', function(ctx, user, next) {
    var body = ctx.req.body;
    if (body && body.verified) {
      body.verified = false;
    }

    var realm;
    if (ctx.instance) {
      realm = ctx.instance.realm;
    }

    User.validateUniqueness(body.email, 'email', true, realm, function(err) {
      next(err);
    });
  });

  User.beforeRemote('prototype.__create__phones', function(ctx, user, next) {
    var body = ctx.req.body;
    if (body && body.verified) {
      body.verified = false;
    }

    var realm;
    if (ctx.instance) {
      realm = ctx.instance.realm;
    }

    User.validateUniqueness(body.phone, 'phone', true, realm, function(err) {
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
