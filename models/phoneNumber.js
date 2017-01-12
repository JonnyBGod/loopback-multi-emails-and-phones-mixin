'use strict';
var loopback = require('loopback/lib/loopback');
var g = require('strong-globalize')();
var crypto = require('crypto');
var utils = require('loopback/lib/utils');
var assert = require('assert');
var path = require('path');

var debug = require('debug')('core:phoneNumber');

module.exports = function(PhoneNumber) {
  /**
   * Verify a phoneNumber's identity by sending them a confirmation phone.
   *
   * ```js
   *    var options = {
   *      to: phoneNumber.phone,
   *      template: 'verify.ejs',
   *      redirect: '/',
   *      tokenGenerator: function (phoneNumber, cb) { cb("random-token"); }
   *    };
   *
   *    phoneNumber.verify(options, next);
   * ```
   *
   * @options {Object} options
   * @property {String} type Must be 'phone' or 'phone'.
   * @property {String} to Phone number to which verification phone is sent.
   * @property {String} from Sender phone numbers, for example
   *   `'noreply@myapp.com'`.
   * @property {String} subject Subject line text.
   * @property {String} text Text of phone.
   * @property {String} template Name of template that displays verification
   *  page, for example, `'verify.ejs'.
   * @property {Function} templateFn A function generating the phone HTML body
   * from `verify()` options object and generated attributes like `options.verifyHref`.
   * It must accept the option object and a callback function with `(err, html)`
   * as parameters
   * @property {String} redirect Page to which phoneNumber will be redirected after
   *  they verify their phone, for example `'/'` for root URI.
   * @property {Function} generateVerificationToken A function to be used to
   *  generate the verification token. It must accept the phoneNumber object and a
   *  callback function. This function should NOT add the token to the phoneNumber
   *  object, instead simply execute the callback with the token! PhoneNumber saving
   *  and phone sending will be handled in the `verify()` method.
   * @callback {Function} fn Callback function.
   * @param {Error} err Error object.
   * @param {Object} object Contains phone, token, uid.
   * @promise
   */
  PhoneNumber.prototype.verify = function(options, fn) {
    fn = fn || utils.createPromiseCallback();

    var phoneNumber = this;
    var phoneNumberModel = this.constructor;
    var registry = phoneNumberModel.registry;
    assert(typeof options === 'object', 'options required when calling phoneNumber.verify()');
    assert(options.to || this.phone,
      'Must include options.to when calling phoneNumber.verify() ' +
      'or the phoneNumber must have an phone property');
    assert(options.from, 'Must include options.from when calling phoneNumber.verify()');

    options.redirect = options.redirect || '/';
    var defaultTemplate = path.join(__dirname, '..', 'templates', 'verifyPhone.ejs');
    options.template = path.resolve(options.template || defaultTemplate);
    options.phoneNumber = this;
    options.protocol = options.protocol || 'http';

    var app = phoneNumberModel.app;
    options.host = options.host || (app && app.get('host')) || 'localhost';
    options.port = options.port || (app && app.get('port')) || 3000;
    options.restApiRoot = options.restApiRoot || (app && app.get('restApiRoot')) || '/api';

    var displayPort = (
      (options.protocol === 'http' && options.port == '80') ||
      (options.protocol === 'https' && options.port == '443')
    ) ? '' : ':' + options.port;

    var urlPath = options.urlPath || joinUrlPath(
      options.restApiRoot,
      phoneNumberModel.http.path,
      phoneNumberModel.sharedClass.findMethodByName('confirm').http.path
    );

    options.verifyHref = options.verifyHref ||
      options.protocol +
      '://' +
      options.host +
      displayPort +
      urlPath +
      '?eid=' +
      phoneNumber.id +
      '&redirect=' +
      options.redirect;

    options.templateFn = options.templateFn || createVerificationPhoneBody;

    // Phone model
    var Phone =
      options.mailer || this.constructor.phone || registry.getModelByType(loopback.Phone);

    // Set a default token generation function if one is not provided
    var tokenGenerator = options.generateVerificationToken ||
      PhoneNumber.generateVerificationToken;

    tokenGenerator(phoneNumber, function(err, token) {
      if (err) { return fn(err); }

      phoneNumber.verificationToken = token;
      phoneNumber.save(function(err) {
        if (err) {
          fn(err);
        } else {
          sendPhone(phoneNumber);
        }
      });
    });

    // TODO - support more verification types
    function sendPhone(phoneNumber) {
      options.verifyHref += '&token=' + phoneNumber.verificationToken;

      options.text = options.text || g.f('Please verify your phone by opening ' +
        'this link in a web browser:\n\t%s', options.verifyHref);

      options.text = options.text.replace(/\{href\}/g, options.verifyHref);

      options.to = options.to || phoneNumber.phone;

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
        // nodphoneer transport plugins.
        delete options.template;

        Phone.send(options, function(err, phone) {
          if (err) {
            fn(err);
          } else {
            fn(null, {phone: phone, token: phoneNumber.verificationToken, uid: phoneNumber.id});
          }
        });
      }
    }
    return fn.promise;
  };

  function createVerificationPhoneBody(options, cb) {
    var template = loopback.template(options.template);
    var body = template(options);
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
    crypto.randomBytes(64, function(err, buf) {
      cb(err, buf && buf.toString('hex'));
    });
  };

  /**
   * Confirm the phoneNumbers' validity.
   *
   * @param {Any} pId
   * @param {String} token The validation token
   * @param {String} redirect URL to redirect the user to once confirmed
   * @callback {Function} callback
   * @param {Error} err
   * @promise
   */
  PhoneNumber.confirm = function(pId, token, redirect, fn) {
    fn = fn || utils.createPromiseCallback();
    this.findById(pId, function(err, phone) {
      if (err) {
        fn(err);
      } else {
        if (phone && phone.verificationToken === token) {
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
          if (phone) {
            err = new Error(g.f('Invalid token: %s', token));
            err.statusCode = 400;
            err.code = 'INVALID_TOKEN';
          } else {
            err = new Error(g.f('PhoneNumber not found: %s', pId));
            err.statusCode = 404;
            err.code = 'PHONENUMBER_NOT_FOUND';
          }
          fn(err);
        }
      }
    });
    return fn.promise;
  };

  PhoneNumber.setup = function() {
    var PhoneNumberModel = this;

    PhoneNumberModel.setter.phone = function(value) {
      this.$phone = value;
    };

    PhoneNumberModel.setter.masked = function(value) {
      this.$masked = value.replace(/(?!^).(?=[^@]+@)/g, '*');
    };

    // Make sure verified is not set by creation
    PhoneNumberModel.beforeRemote('create', function(ctx, user, next) {
      var body = ctx.req.body;
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
      next();
    } else {
      var isPartialUpdateChangingPhone = ctx.data && 'phone' in ctx.data;
      var isFullReplaceChangingPhone = !!ctx.instance;

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
        next();
      }
    }
  });
};

// TODO: proper phone number validator
function phoneValidator(err) {
  var value = this.phone;
  if (value == null)
    return;
  if (typeof value !== 'string')
    return err('string');
  if (value === '') return;
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
