'use strict';
var isEmail = require('isemail');
var loopback = require('loopback/lib/loopback');
var g = require('strong-globalize')();
var crypto = require('crypto');
var utils = require('loopback/lib/utils');
var assert = require('assert');
var path = require('path');

var debug = require('debug')('core:emailAddress');

module.exports = function(EmailAddress) {
  /**
   * Verify a emailAddress's identity by sending them a confirmation email.
   *
   * ```js
   *    var options = {
   *      to: emailAddress.email,
   *      template: 'verify.ejs',
   *      redirect: '/',
   *      tokenGenerator: function (emailAddress, cb) { cb("random-token"); }
   *    };
   *
   *    emailAddress.verify(options, next);
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
   * @property {String} redirect Page to which emailAddress will be redirected after
   *  they verify their email, for example `'/'` for root URI.
   * @property {Function} generateVerificationToken A function to be used to
   *  generate the verification token. It must accept the emailAddress object and a
   *  callback function. This function should NOT add the token to the emailAddress
   *  object, instead simply execute the callback with the token! EmailAddress saving
   *  and email sending will be handled in the `verify()` method.
   * @callback {Function} fn Callback function.
   * @param {Error} err Error object.
   * @param {Object} object Contains email, token, uid.
   * @promise
   */
  EmailAddress.prototype.verify = function(options, fn) {
    fn = fn || utils.createPromiseCallback();

    var emailAddress = this;
    var emailAddressModel = this.constructor;
    var registry = emailAddressModel.registry;
    assert(typeof options === 'object', 'options required when calling emailAddress.verify()');
    assert(options.to || this.email,
      'Must include options.to when calling emailAddress.verify() ' +
      'or the emailAddress must have an email property');
    assert(options.from, 'Must include options.from when calling emailAddress.verify()');

    options.redirect = options.redirect || '/';
    var defaultTemplate = path.join(__dirname, '..', 'templates', 'verifyEmail.ejs');
    options.template = path.resolve(options.template || defaultTemplate);
    options.emailAddress = this;
    options.protocol = options.protocol || 'http';

    var app = emailAddressModel.app;
    options.host = options.host || (app && app.get('host')) || 'localhost';
    options.port = options.port || (app && app.get('port')) || 3000;
    options.restApiRoot = options.restApiRoot || (app && app.get('restApiRoot')) || '/api';

    var displayPort = (
      (options.protocol === 'http' && options.port == '80') ||
      (options.protocol === 'https' && options.port == '443')
    ) ? '' : ':' + options.port;

    var urlPath = options.urlPath || joinUrlPath(
      options.restApiRoot,
      emailAddressModel.http.path,
      emailAddressModel.sharedClass.findMethodByName('confirm').http.path
    );

    options.verifyHref = options.verifyHref ||
      options.protocol +
      '://' +
      options.host +
      displayPort +
      urlPath +
      '?eid=' +
      emailAddress.id +
      '&redirect=' +
      options.redirect;

    options.templateFn = options.templateFn || createVerificationEmailBody;

    // Email model
    var Email =
      options.mailer || this.constructor.email || registry.getModelByType(loopback.Email);

    // Set a default token generation function if one is not provided
    var tokenGenerator = options.generateVerificationToken ||
      EmailAddress.generateVerificationToken;

    tokenGenerator(emailAddress, function(err, token) {
      if (err) { return fn(err); }

      emailAddress.verificationToken = token;
      emailAddress.save(function(err) {
        if (err) {
          fn(err);
        } else {
          sendEmail(emailAddress);
        }
      });
    });

    // TODO - support more verification types
    function sendEmail(emailAddress) {
      options.verifyHref += '&token=' + emailAddress.verificationToken;

      options.text = options.text || g.f('Please verify your email by opening ' +
        'this link in a web browser:\n\t%s', options.verifyHref);

      options.text = options.text.replace(/\{href\}/g, options.verifyHref);

      options.to = options.to || emailAddress.email;

      options.subject = options.subject || g.f('Thanks for Registering');

      options.headers = options.headers || {};

      options.templateFn(options, function(err, html) {
        if (err) {
          fn(err);
        } else {
          setHtmlContentAndSend(html);
        }
      });

      function setHtmlContentAndSend(html) {
        options.html = html;

        // Remove options.template to prevent rejection by certain
        // nodemailer transport plugins.
        delete options.template;

        Email.send(options, function(err, email) {
          if (err) {
            fn(err);
          } else {
            fn(null, {email: email, token: emailAddress.verificationToken, uid: emailAddress.id});
          }
        });
      }
    }
    return fn.promise;
  };

  function createVerificationEmailBody(options, cb) {
    var template = loopback.template(options.template);
    var body = template(options);
    cb(null, body);
  }

  /**
   * A default verification token generator which accepts the emailAddress the token is
   * being generated for and a callback function to indicate completion.
   * This one uses the crypto library and 64 random bytes (converted to hex)
   * for the token. When used in combination with the emailAddress.verify() method this
   * function will be called with the `emailAddress` object as it's context (`this`).
   *
   * @param {object} emailAddress The EmailAddress this token is being generated for.
   * @param {Function} cb The generator must pass back the new token with this function call
   */
  EmailAddress.generateVerificationToken = function(emailAddress, cb) {
    crypto.randomBytes(64, function(err, buf) {
      cb(err, buf && buf.toString('hex'));
    });
  };

  /**
   * Confirm the emailAddress's validity.
   *
   * @param {Any} userId
   * @param {String} token The validation token
   * @param {String} redirect URL to redirect the user to once confirmed
   * @callback {Function} callback
   * @param {Error} err
   * @promise
   */
  EmailAddress.confirm = function(eid, token, redirect, fn) {
    fn = fn || utils.createPromiseCallback();
    this.findById(eid, function(err, email) {
      if (err) {
        fn(err);
      } else {
        if (email && email.verificationToken === token) {
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
          if (email) {
            err = new Error(g.f('Invalid token: %s', token));
            err.statusCode = 400;
            err.code = 'INVALID_TOKEN';
          } else {
            err = new Error(g.f('EmailAddress not found: %s', eid));
            err.statusCode = 404;
            err.code = 'EMAILADDRESS_NOT_FOUND';
          }
          fn(err);
        }
      }
    });
    return fn.promise;
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
