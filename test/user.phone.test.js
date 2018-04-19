// Copyright IBM Corp. 2013,2016. All Rights Reserved.
// Node module: loopback
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
var assert = require('assert');
var expect = require('./helpers/expect');
var request = require('supertest');
var loopback = require('loopback');
var async = require('async');
var url = require('url');
var extend = require('util')._extend;
const Promise = require('bluebird');
const waitForEvent = require('./helpers/wait-for-event');

var MultiEmailsAndPhones = require('../multi-emails-and-phones.js');

var User, AccessToken;

describe('User', function() {
  this.timeout(10000);

  var validCredentialsPhone = '(817) 569-8900';
  var validCredentials = {phone: validCredentialsPhone, password: 'bar'};
  var validCredentialsPhoneVerified = {
    phone: '(817) 569-8901', password: 'bar1', phoneVerified: true};
  var validCredentialsPhoneVerifiedOverREST = {
    phone: '(817) 569-8902', password: 'bar2', phoneVerified: true};
  var validCredentialsWithRealm = {
    phone: '(817) 569-8903', password: 'bar', realm: 'foobar'};
  var validCredentialsWithTTL = {phone: '(817) 569-8900', password: 'bar', ttl: 3600};
  var validCredentialsWithTTLAndScope = {
    phone: '(817) 569-8900', password: 'bar', ttl: 3600, scope: 'all'};
  var validMixedCasePhoneCredentials = {phone: '(817) 569-8970', password: 'bar'};
  var invalidCredentials = {phone: '(817) 569-8901', password: 'invalid'};
  var incompleteCredentials = {password: 'bar1'};
  var validCredentialsUser, validCredentialsPhoneVerifiedUser, user;

  // Create a local app variable to prevent clashes with the global
  // variable shared by all tests. While this should not be necessary if
  // the tests were written correctly, it turns out that's not the case :(
  var app = null;

  beforeEach(function setupAppAndModels() {
    // override the global app object provided by test/support.js
    // and create a local one that does not share state with other tests
    app = loopback({localRegistry: true, loadBuiltinModels: true});
    app.set('remoting', {errorHandler: {debug: true, log: false}});
    app.dataSource('db', {connector: 'memory'});

    // setup Phone model, it's needed by User tests
    app.dataSource('email', {
      connector: loopback.Mail,
      transports: [{type: 'STUB'}],
    });
    var Phone = app.registry.getModel('Email');
    app.model(Phone, {dataSource: 'email'});

    // attach User and related models
    User = app.registry.createModel({
      name: 'TestUser',
      base: 'User',
      properties: {
        // Use a custom id property to verify that User methods
        // are correctly looking up the primary key
        pk: {type: 'String', defaultFn: 'guid', id: true},
      },
      http: {path: 'test-users'},
      // forceId is set to false for the purpose of updating the same affected user within the
      // `Phone Update` test cases.
      forceId: false,
      // Speed up the password hashing algorithm for tests
      saltWorkFactor: 4,
    });
    app.model(User, {dataSource: 'db'});

    AccessToken = app.registry.getModel('AccessToken');
    app.model(AccessToken, {dataSource: 'db'});

    User.phone = Phone;

    // Update the AccessToken relation to use the subclass of User
    AccessToken.belongsTo(User, {as: 'user', foreignKey: 'userId'});
    User.hasMany(AccessToken, {as: 'accessTokens', foreignKey: 'userId'});

    /**
     * Setup Mixin
     */
    MultiEmailsAndPhones(User, true);

    // Speed up the password hashing algorithm
    // for tests using the built-in User model
    User.settings.saltWorkFactor = 4;

    // allow many User.afterRemote's to be called
    User.setMaxListeners(0);

    app.enableAuth({dataSource: 'db'});
    app.use(loopback.token({model: AccessToken}));
    app.use(loopback.rest());

    // create 2 users: with and without verified phone
    return Promise.map(
      [validCredentials, validCredentialsPhoneVerified],
      credentials => User.create(credentials)
    ).then(users => {
      validCredentialsUser = user = users[0];
      validCredentialsPhoneVerifiedUser = users[1];
    });
  });

  describe('User.create', function() {
    it('Create a new user', function(done) {
      User.create({phone: '(817) 569-8910', password: 'bar'}, function(err, user) {
        assert(!err);
        assert(user.pk);
        assert(user.phoneNumbers);

        done();
      });
    });

    it('Create a new user', function(done) {
      User.create({phone: '(817) 569-8920', password: 'bar'}, function(err, user) {
        if (err) return done(err);

        assert(user.pk);
        assert.equal(user.phoneNumbers[0].phone, user.phoneNumbers[0].phone.toLowerCase());

        done();
      });
    });

    it('Phone is required', function(done) {
      User.create({password: '123'}, function(err) {
        assert(err);
        assert.equal(err.name, 'ValidationError');
        assert.equal(err.statusCode, 422);
        assert.equal(err.details.context, User.modelName);
        assert.deepEqual(err.details.codes.email, ['presence']);

        done();
      });
    });

    // will change in future versions where password will be optional by default
    it('Password is required', function(done) {
      var u = new User({phone: '(817) 569-8800'});

      User.create({phone: '(817) 569-8810'}, function(err) {
        assert(err);

        done();
      });
    });

    it('Requires a valid phone', function(done) {
      User.create({phone: '6123-6123', password: '123'}, function(err) {
        assert(err);
        assert.equal(err.name, 'ValidationError');
        assert.equal(err.statusCode, 422);
        assert.equal(err.details.context, User.modelName);
        assert.deepEqual(err.details.codes.phone, ['custom.phone']);
        done();
      });
    });

    it('allows TLD domains in phone', function() {
      return User.create({
        phone: '(817) 569-8929',
        password: '123',
      });
    });

    it('Requires a unique phone', function(done) {
      User.create({phone: '(817) 569-8930', password: 'foobar'}, function() {
        User.create({phone: '(817) 569-8930', password: 'batbaz'}, function(err) {
          assert(err, 'should error because the phone is not unique!');

          done();
        });
      });
    });

    it('Requires a unique phone', function(done) {
      User.create({phone: '(817) 569-8940', password: 'foobar'}, function(err) {
        if (err) return done(err);

        User.create({phone: '(817) 569-8940', password: 'batbaz'}, function(err) {
          assert(err, 'should error because the phone is not unique!');

          done();
        });
      });
    });

    it('Requires a unique username', function(done) {
      User.create({phone: '(817) 569-8930', username: 'abc', password: 'foobar'}, function() {
        User.create({phone: '(817) 569-8941', username: 'abc',  password: 'batbaz'}, function(err) {
          assert(err, 'should error because the username is not unique!');

          done();
        });
      });
    });

    it('Requires a password to login with basic auth', function(done) {
      User.create({phone: '(817) 569-8942'}, function(err) {
        User.login({phone: '(817) 569-8942'}, function(err, accessToken) {
          assert(!accessToken, 'should not create a accessToken without a valid password');
          assert(err, 'should not login without a password');
          assert.equal(err.code, 'LOGIN_FAILED');

          done();
        });
      });
    });

    it('Hashes the given password', function() {
      var u = new User({username: 'foo', password: 'bar'});
      assert(u.password !== 'bar');
    });

    it('does not hash the password if it\'s already hashed', function() {
      var u1 = new User({username: 'foo', password: 'bar'});
      assert(u1.password !== 'bar');
      var u2 = new User({username: 'foo', password: u1.password});
      assert(u2.password === u1.password);
    });

    it('invalidates the user\'s accessToken when the user is deleted By id', function(done) {
      var usersId;
      async.series([
        function(next) {
          User.create({phone: '(817) 569-8942', password: 'bar'}, function(err, user) {
            usersId = user.pk;
            next(err);
          });
        },
        function(next) {
          User.login({phone: '(817) 569-8942', password: 'bar'}, function(err, accessToken) {
            if (err) return next(err);
            assert(accessToken.userId);
            next();
          });
        },
        function(next) {
          User.deleteById(usersId, function(err) {
            next(err);
          });
        },
        function(next) {
          User.findById(usersId, function(err, userFound)  {
            if (err) return next(err);
            expect(userFound).to.equal(null);
            AccessToken.find({where: {userId: usersId}}, function(err, tokens) {
              if (err) return next(err);
              expect(tokens.length).to.equal(0);
              next();
            });
          });
        },
      ], function(err) {
        if (err) return done(err);
        done();
      });
    });

    it('invalidates the user\'s accessToken when the user is deleted all', function(done) {
      var userIds = [];
      var users;
      async.series([
        function(next) {
          User.create([
            {name: 'myname', phone: '(817) 569-8942', password: 'bar'},
            {name: 'myname', phone: '(817) 569-8924', password: 'bar'},
          ], function(err, createdUsers) {
            users = createdUsers;
            userIds = createdUsers.map(function(u) {
              return u.pk;
            });
            next(err);
          });
        },
        function(next) {
          User.login({phone: '(817) 569-8942', password: 'bar'}, function(err, accessToken) {
            if (err) return next(err);
            assertGoodToken(accessToken, users[0]);
            next();
          });
        },
        function(next) {
          User.login({phone: '(817) 569-8924', password: 'bar'}, function(err, accessToken) {
            if (err) return next(err);
            assertGoodToken(accessToken, users[1]);
            next();
          });
        },
        function(next) {
          User.deleteAll({name: 'myname'}, function(err, user) {
            next(err);
          });
        },
        function(next) {
          User.find({where: {name: 'myname'}}, function(err, userFound)  {
            if (err) return next(err);
            expect(userFound.length).to.equal(0);
            AccessToken.find({where: {userId: {inq: userIds}}}, function(err, tokens) {
              if (err) return next(err);
              expect(tokens.length).to.equal(0);
              next();
            });
          });
        },
      ], function(err) {
        if (err) return done(err);
        done();
      });
    });

    describe('custom password hash', function() {
      var defaultHashPassword, defaultValidatePassword;

      beforeEach(function() {
        defaultHashPassword = User.hashPassword;
        defaultValidatePassword = User.validatePassword;

        User.hashPassword = function(plain) {
          return plain.toUpperCase();
        };

        User.validatePassword = function(plain) {
          if (!plain || plain.length < 3) {
            throw new Error('Password must have at least 3 chars');
          }
          return true;
        };
      });

      afterEach(function() {
        User.hashPassword = defaultHashPassword;
        User.validatePassword = defaultValidatePassword;
      });

      it('Reports invalid password', function() {
        try {
          var u = new User({username: 'foo', password: 'aa'});
          assert(false, 'Error should have been thrown');
        } catch (e) {
          // Ignore
        }
      });

      it('Hashes the given password', function() {
        var u = new User({username: 'foo', password: 'bar'});
        assert(u.password === 'BAR');
      });
    });

    it('Create a user over REST should remove phone verified property', function(done) {
      request(app)
        .post('/test-users')
        .expect('Content-Type', /json/)
        .expect(200)
        .send(validCredentialsPhoneVerifiedOverREST)
        .end(function(err, res) {
          if (err) return done(err);

          assert(!res.body.verified);

          done();
        });
    });
  });

  describe('Password length validation', function() {
    var pass72Char = new Array(70).join('a') + '012';
    var pass73Char = pass72Char + '3';
    var passTooLong = pass72Char + 'WXYZ1234';

    it('rejects empty passwords creation', function(done) {
      User.create({phone: '(817) 569-8942', password: ''}, function(err) {
        expect(err.code).to.equal('INVALID_PASSWORD');
        expect(err.statusCode).to.equal(422);
        done();
      });
    });

    it('rejects updating with empty password', function(done) {
      User.create({phone: '(817) 569-8920', password: pass72Char}, function(err, userCreated) {
        if (err) return done(err);
        userCreated.updateAttribute('password', '', function(err, userUpdated) {
          expect(err.code).to.equal('INVALID_PASSWORD');
          expect(err.statusCode).to.equal(422);
          done();
        });
      });
    });

    it('rejects updating with empty password using replaceAttributes', function(done) {
      User.create({phone: '(817) 569-8921', password: pass72Char}, function(err, userCreated) {
        if (err) return done(err);
        userCreated.replaceAttributes({'password': ''}, function(err, userUpdated) {
          expect(err.code).to.equal('INVALID_PASSWORD');
          expect(err.statusCode).to.equal(422);
          done();
        });
      });
    });

    it('rejects updating with empty password using updateOrCreate', function(done) {
      User.create({phone: '(817) 569-8921', password: pass72Char}, function(err, userCreated) {
        if (err) return done(err);
        User.updateOrCreate({id: userCreated.id, 'password': ''}, function(err, userUpdated) {
          expect(err.code).to.equal('INVALID_PASSWORD');
          expect(err.statusCode).to.equal(422);
          done();
        });
      });
    });

    it('rejects updating with empty password using updateAll', function(done) {
      User.create({phone: '(817) 569-8921', password: pass72Char}, function(err, userCreated) {
        if (err) return done(err);
        User.updateAll({where: {id: userCreated.id}}, {'password': ''}, function(err, userUpdated) {
          expect(err.code).to.equal('INVALID_PASSWORD');
          expect(err.statusCode).to.equal(422);
          done();
        });
      });
    });

    it('rejects passwords longer than 72 characters', function(done) {
      User.create({phone: '(817) 569-8942', password: pass73Char}, function(err) {
        expect(err.code).to.equal('PASSWORD_TOO_LONG');
        expect(err.statusCode).to.equal(422);
        done();
      });
    });

    it('rejects a new user with password longer than 72 characters', function(done) {
      try {
        var u = new User({username: 'foo', password: pass73Char});
        assert(false, 'Error should have been thrown');
      } catch (e) {
        expect(e).to.match(/password entered was too long/);
        done();
      }
    });

    it('accepts passwords that are exactly 72 characters long', function(done) {
      User.create({phone: '(817) 569-8942', password: pass72Char}, function(err, user) {
        if (err) return done(err);
        User.findById(user.pk, function(err, userFound)  {
          if (err) return done(err);
          assert(userFound);
          done();
        });
      });
    });

    it('allows login with password exactly 72 characters long', function(done) {
      User.create({phone: '(817) 569-8942', password: pass72Char}, function(err, user) {
        if (err) return done(err);
        User.login({phone: '(817) 569-8942', password: pass72Char}, function(err, accessToken) {
          if (err) return done(err);
          assertGoodToken(accessToken, user);
          done();
        });
      });
    });

    it('rejects password reset when password is more than 72 chars', function(done) {
      User.create({phone: '(817) 569-8942', password: pass72Char}, function(err) {
        if (err) return done(err);
        User.resetPassword({phone: '(817) 569-8942', password: pass73Char}, function(err) {
          assert(err);
          expect(err).to.match(/password entered was too long/);
          done();
        });
      });
    });

    it('rejects changePassword when new password is longer than 72 chars', function() {
      return User.create({phone: '(817) 569-8920', password: pass72Char})
        .then(u => u.changePassword(pass72Char, pass73Char))
        .then(
          success => { throw new Error('changePassword should have failed'); },
          err => {
            expect(err.message).to.match(/password entered was too long/);

            // workaround for chai problem
            //   object tested must be an array, an object, or a string,
            //   but error given
            const props = Object.assign({}, err);
            expect(props).to.contain({
              code: 'PASSWORD_TOO_LONG',
              statusCode: 422,
            });
          });
    });

    it('rejects setPassword when new password is longer than 72 chars', function() {
      return User.create({phone: '(817) 569-8920', password: pass72Char})
        .then(u => u.setPassword(pass73Char))
        .then(
          success => { throw new Error('setPassword should have failed'); },
          err => {
            expect(err.message).to.match(/password entered was too long/);

            // workaround for chai problem
            //   object tested must be an array, an object, or a string,
            //   but error given
            const props = Object.assign({}, err);
            expect(props).to.contain({
              code: 'PASSWORD_TOO_LONG',
              statusCode: 422,
            });
          });
    });
  });

  describe('Access-hook for queries with phone', function() {
    it('Should not throw an error if the query does not contain {where: }', function(done) {
      User.find({}, function(err) {
        if (err) done(err);

        done();
      });
    });
  });

  describe('User.login', function() {
    it('Login a user by providing credentials', function(done) {
      User.login(validCredentials, function(err, accessToken) {
        assertGoodToken(accessToken, validCredentialsUser);

        done();
      });
    });

    it('Try to login with invalid phone', function(done) {
      User.login(validMixedCasePhoneCredentials, function(err, accessToken) {
        assert(err);

        done();
      });
    });

    it('Login a user by providing credentials with TTL', function(done) {
      User.login(validCredentialsWithTTL, function(err, accessToken) {
        assertGoodToken(accessToken, validCredentialsUser);
        assert.equal(accessToken.ttl, validCredentialsWithTTL.ttl);

        done();
      });
    });

    it('honors default `createAccessToken` implementation', function(done) {
      User.login(validCredentialsWithTTL, function(err, accessToken) {
        assert(accessToken.userId);
        assert(accessToken.id);

        User.findById(accessToken.userId, function(err, user) {
          user.createAccessToken(120, function(err, accessToken) {
            assertGoodToken(accessToken, validCredentialsUser);
            assert.equal(accessToken.ttl, 120);

            done();
          });
        });
      });
    });

    it('honors default `createAccessToken` implementation - promise variant', function(done) {
      User.login(validCredentialsWithTTL, function(err, accessToken) {
        assert(accessToken.userId);
        assert(accessToken.id);

        User.findById(accessToken.userId, function(err, user) {
          user.createAccessToken(120)
            .then(function(accessToken) {
              assertGoodToken(accessToken, validCredentialsUser);
              assert.equal(accessToken.ttl, 120);

              done();
            })
            .catch(function(err) {
              done(err);
            });
        });
      });
    });

    it('Login a user using a custom createAccessToken', function(done) {
      var createToken = User.prototype.createAccessToken; // Save the original method
      // Override createAccessToken
      User.prototype.createAccessToken = function(ttl, cb) {
        // Reduce the ttl by half for testing purpose
        this.accessTokens.create({ttl: ttl / 2}, cb);
      };
      User.login(validCredentialsWithTTL, function(err, accessToken) {
        assertGoodToken(accessToken, validCredentialsUser);
        assert.equal(accessToken.ttl, 1800);

        User.findById(accessToken.userId, function(err, user) {
          user.createAccessToken(120, function(err, accessToken) {
            assertGoodToken(accessToken, validCredentialsUser);
            assert.equal(accessToken.ttl, 60);
            // Restore create access token
            User.prototype.createAccessToken = createToken;

            done();
          });
        });
      });
    });

    it('Login a user using a custom createAccessToken with options',
      function(done) {
        var createToken = User.prototype.createAccessToken; // Save the original method
        // Override createAccessToken
        User.prototype.createAccessToken = function(ttl, options, cb) {
          // Reduce the ttl by half for testing purpose
          this.accessTokens.create({ttl: ttl / 2, scopes: [options.scope]}, cb);
        };
        User.login(validCredentialsWithTTLAndScope, function(err, accessToken) {
          assertGoodToken(accessToken, validCredentialsUser);
          assert.equal(accessToken.ttl, 1800);
          assert.deepEqual(accessToken.scopes, ['all']);

          User.findById(accessToken.userId, function(err, user) {
            user.createAccessToken(120, {scope: 'default'}, function(err, accessToken) {
              assertGoodToken(accessToken, validCredentialsUser);
              assert.equal(accessToken.ttl, 60);
              assert.deepEqual(accessToken.scopes, ['default']);
              // Restore create access token
              User.prototype.createAccessToken = createToken;

              done();
            });
          });
        });
      });

    it('Login should only allow correct credentials', function(done) {
      User.login(invalidCredentials, function(err, accessToken) {
        assert(err);
        assert.equal(err.code, 'LOGIN_FAILED');
        assert(!accessToken);

        done();
      });
    });

    it('Login should only allow correct credentials - promise variant', function(done) {
      User.login(invalidCredentials)
        .then(function(accessToken) {
          expect(accessToken, 'accessToken').to.not.exist();

          done();
        })
        .catch(function(err) {
          expect(err, 'err').to.exist();
          expect(err).to.have.property('code', 'LOGIN_FAILED');

          done();
        });
    });

    it('Login a user providing incomplete credentials', function(done) {
      User.login(incompleteCredentials, function(err, accessToken) {
        expect(err, 'err').to.exist();
        expect(err).to.have.property('code', 'USERNAME_EMAIL_PHONE_REQUIRED');

        done();
      });
    });

    it('Login a user providing incomplete credentials - promise variant', function(done) {
      User.login(incompleteCredentials)
        .then(function(accessToken) {
          expect(accessToken, 'accessToken').to.not.exist();

          done();
        })
        .catch(function(err) {
          expect(err, 'err').to.exist();
          expect(err).to.have.property('code', 'USERNAME_EMAIL_PHONE_REQUIRED');

          done();
        });
    });

    it('Login a user over REST by providing credentials', function(done) {
      request(app)
        .post('/test-users/login')
        .expect('Content-Type', /json/)
        .expect(200)
        .send(validCredentials)
        .end(function(err, res) {
          if (err) return done(err);

          var accessToken = res.body;

          assertGoodToken(accessToken, validCredentialsUser);
          assert(accessToken.user === undefined);

          done();
        });
    });

    it('Login a user over REST by providing invalid credentials', function(done) {
      request(app)
        .post('/test-users/login')
        .expect('Content-Type', /json/)
        .expect(401)
        .send(invalidCredentials)
        .end(function(err, res) {
          if (err) return done(err);

          var errorResponse = res.body.error;
          assert.equal(errorResponse.code, 'LOGIN_FAILED');

          done();
        });
    });

    it('Login a user over REST by providing incomplete credentials', function(done) {
      request(app)
        .post('/test-users/login')
        .expect('Content-Type', /json/)
        .expect(400)
        .send(incompleteCredentials)
        .end(function(err, res) {
          if (err) return done(err);

          var errorResponse = res.body.error;
          assert.equal(errorResponse.code, 'USERNAME_EMAIL_PHONE_REQUIRED');

          done();
        });
    });

    it('Login a user over REST with the wrong Content-Type', function(done) {
      request(app)
        .post('/test-users/login')
        .set('Content-Type', null)
        .expect('Content-Type', /json/)
        .expect(400)
        .send(JSON.stringify(validCredentials))
        .end(function(err, res) {
          if (err) return done(err);

          var errorResponse = res.body.error;
          assert.equal(errorResponse.code, 'USERNAME_EMAIL_PHONE_REQUIRED');

          done();
        });
    });

    it('Returns current user when `include` is `USER`', function(done) {
      request(app)
        .post('/test-users/login?include=USER')
        .send(validCredentials)
        .expect(200)
        .expect('Content-Type', /json/)
        .end(function(err, res) {
          if (err) return done(err);

          var token = res.body;
          expect(token.user, 'body.user').to.not.equal(undefined);
          expect(token.user.phoneNumbers[0], 'body.user.phoneNumbers[0]')
            .to.have.property('masked');

          done();
        });
    });

    it('should handle multiple `include`', function(done) {
      request(app)
        .post('/test-users/login?include=USER&include=Post')
        .send(validCredentials)
        .expect(200)
        .expect('Content-Type', /json/)
        .end(function(err, res) {
          if (err) return done(err);

          var token = res.body;
          expect(token.user, 'body.user').to.not.equal(undefined);
          expect(token.user.phoneNumbers[0], 'body.user.phoneNumbers[0]')
            .to.have.property('masked');

          done();
        });
    });

    it('allows login with password too long but created in old LB version',
      function(done) {
        var bcrypt = require('bcryptjs');
        var longPassword = new Array(80).join('a');
        var oldHash = bcrypt.hashSync(longPassword, bcrypt.genSaltSync(1));

        User.create({phone: '(817) 569-8942', password: oldHash}, function(err) {
          if (err) return done(err);
          User.login({phone: '(817) 569-8942', password: longPassword}, function(err, accessToken) {
            if (err) return done(err);
            assert(accessToken.id);
            // we are logged in, the test passed
            done();
          });
        });
      });
  });

  function assertGoodToken(accessToken, user) {
    if (accessToken instanceof AccessToken) {
      accessToken = accessToken.toJSON();
    }
    expect(accessToken).to.have.property('userId', user.pk);
    assert(accessToken.id);
    assert.equal(accessToken.id.length, 64);
  }

  describe('User.login requiring phone verification', function() {
    beforeEach(function() {
      User.settings.emailVerificationRequired = true;
    });

    afterEach(function() {
      User.settings.emailVerificationRequired = false;
    });

    it('requires valid and complete credentials for phone verification', function(done) {
      User.login({phone: validCredentialsPhone}, function(err, accessToken) {
        // strongloop/loopback#931
        // error message should be "login failed"
        // and not "login failed as the phone has not been verified"
        assert(err && !/verified/.test(err.message),
          'expecting "login failed" error message, received: "' + err.message + '"');
        assert.equal(err.code, 'LOGIN_FAILED');
        // as login is failing because of invalid credentials it should to return
        // the user id in the error message
        assert.equal(err.details, undefined);

        done();
      });
    });

    it('requires valid and complete credentials for phone verification - promise variant',
      function(done) {
        User.login({phone: validCredentialsPhone})
          .then(function(accessToken) {
            done();
          })
          .catch(function(err) {
            // strongloop/loopback#931
            // error message should be "login failed" and not "login failed as the phone has not been verified"
            assert(err && !/verified/.test(err.message),
              'expecting "login failed" error message, received: "' + err.message + '"');
            assert.equal(err.code, 'LOGIN_FAILED');
            assert.equal(err.details, undefined);
            done();
          });
      });

    it('does not login a user with unverified phone but provides userId', function() {
      return User.login(validCredentials).then(
        function(user) {
          throw new Error('User.login() should have failed');
        },
        function(err, accessToken) {
          err = Object.assign({}, err);
          expect(err).to.eql({
            statusCode: 401,
            code: 'LOGIN_FAILED_PHONE_NOT_VERIFIED',
            details: {
              userId: validCredentialsUser.pk,
            },
          });
        }
      );
    });

    xit('login a user with verified phone', function(done) {
      User.login(validCredentialsPhoneVerified, function(err, accessToken) {
        assertGoodToken(accessToken, validCredentialsPhoneVerifiedUser);

        done();
      });
    });

    xit('login a user with verified phone - promise variant', function(done) {
      User.login(validCredentialsPhoneVerified)
        .then(function(accessToken) {
          assertGoodToken(accessToken, validCredentialsPhoneVerifiedUser);

          done();
        })
        .catch(function(err) {
          done(err);
        });
    });

    xit('login a user over REST when phone verification is required', function(done) {
      request(app)
        .post('/test-users/login')
        .expect('Content-Type', /json/)
        .expect(200)
        .send(validCredentialsPhoneVerified)
        .end(function(err, res) {
          if (err) return done(err);

          var accessToken = res.body;

          assertGoodToken(accessToken, validCredentialsPhoneVerifiedUser);
          assert(accessToken.user === undefined);

          done();
        });
    });

    it('login user over REST require complete and valid credentials ' +
    'for phone verification error message',
    function(done) {
      request(app)
        .post('/test-users/login')
        .expect('Content-Type', /json/)
        .expect(401)
        .send({phone: validCredentialsPhone})
        .end(function(err, res) {
          if (err) return done(err);

          // strongloop/loopback#931
          // error message should be "login failed"
          // and not "login failed as the phone has not been verified"
          var errorResponse = res.body.error;
          assert(errorResponse && !/verified/.test(errorResponse.message),
            'expecting "login failed" error message, received: "' + errorResponse.message + '"');
          assert.equal(errorResponse.code, 'LOGIN_FAILED');

          done();
        });
    });

    it('login a user over REST without phone verification when it is required', function(done) {
      // make sure the app is configured in production mode
      app.set('remoting', {errorHandler: {debug: false, log: false}});

      request(app)
        .post('/test-users/login')
        .expect('Content-Type', /json/)
        .expect(401)
        .send(validCredentials)
        .end(function(err, res) {
          if (err) return done(err);

          var errorResponse = res.body.error;

          // extracting code and details error response
          let errorExcerpts = {
            code: errorResponse.code,
            details: errorResponse.details,
          };

          expect(errorExcerpts).to.eql({
            code: 'LOGIN_FAILED_PHONE_NOT_VERIFIED',
            details: {
              userId: validCredentialsUser.pk,
            },
          });

          done();
        });
    });
  });

  describe('User.login requiring realm', function() {
    var User, AccessToken;

    beforeEach(function() {
      User = app.registry.createModel('RealmUser', {}, {
        base: 'TestUser',
        realmRequired: true,
        realmDelimiter: ':',
      });

      AccessToken = app.registry.createModel('RealmAccessToken', {}, {
        base: 'AccessToken',
      });

      app.model(AccessToken, {dataSource: 'db'});
      app.model(User, {dataSource: 'db'});

      // Update the AccessToken relation to use the subclass of User
      AccessToken.belongsTo(User, {as: 'user', foreignKey: 'userId'});
      User.hasMany(AccessToken, {as: 'accessTokens', foreignKey: 'userId'});

      // allow many User.afterRemote's to be called
      User.setMaxListeners(0);
    });

    var realm1User = {
      realm: 'realm1',
      username: 'foo100',
      phone: '(817) 569-8950',
      password: 'pass100',
    };

    var realm11User = {
      realm: 'realm1',
      username: 'foo200',
      phone: '(817) 569-8950',
      password: 'pass100',
    };

    var realm2User = {
      realm: 'realm2',
      username: 'foo100',
      phone: '(817) 569-8950',
      password: 'pass200',
    };

    var credentialWithoutRealm = {
      username: 'foo100',
      phone: '(817) 569-8950',
      password: 'pass100',
    };

    var credentialWithBadPass = {
      realm: 'realm1',
      username: 'foo100',
      phone: '(817) 569-8950',
      password: 'pass001',
    };

    var credentialWithBadRealm = {
      realm: 'realm3',
      username: 'foo100',
      phone: '(817) 569-8950',
      password: 'pass100',
    };

    var credentialWithRealm = {
      realm: 'realm1',
      username: 'foo100',
      password: 'pass100',
    };

    var credentialRealmInUsername = {
      username: 'realm1:foo100',
      password: 'pass100',
    };

    var credentialRealmInPhone = {
      phone: 'realm1:(817) 569-8950',
      password: 'pass100',
    };

    var user1 = null;
    beforeEach(function(done) {
      User.create(realm1User, function(err, u) {
        if (err) return done(err);

        user1 = u;
        User.create(realm2User, done);
      });
    });

    it('honors unique phone for realm', function(done) {
      User.create(realm11User, function(err, u) {
        assert(err);
        assert(err.message.match(/Phone already exists/));
        done();
      });
    });

    it('rejects a user by without realm', function(done) {
      User.login(credentialWithoutRealm, function(err, accessToken) {
        assert(err);
        assert.equal(err.code, 'REALM_REQUIRED');

        done();
      });
    });

    it('rejects a user by with bad realm', function(done) {
      User.login(credentialWithBadRealm, function(err, accessToken) {
        assert(err);
        assert.equal(err.code, 'LOGIN_FAILED');

        done();
      });
    });

    it('rejects a user by with bad pass', function(done) {
      User.login(credentialWithBadPass, function(err, accessToken) {
        assert(err);
        assert.equal(err.code, 'LOGIN_FAILED');

        done();
      });
    });

    it('logs in a user by with realm', function(done) {
      User.login(credentialWithRealm, function(err, accessToken) {
        assertGoodToken(accessToken, user1);

        done();
      });
    });

    it('logs in a user by with realm in username', function(done) {
      User.login(credentialRealmInUsername, function(err, accessToken) {
        assertGoodToken(accessToken, user1);

        done();
      });
    });

    it('logs in a user by with realm in phone', function(done) {
      User.login(credentialRealmInPhone, function(err, accessToken) {
        assertGoodToken(accessToken, user1);

        done();
      });
    });

    describe('User.login with realmRequired but no realmDelimiter', function() {
      beforeEach(function() {
        User.settings.realmDelimiter = undefined;
      });

      afterEach(function() {
        User.settings.realmDelimiter = ':';
      });

      it('logs in a user by with realm', function(done) {
        User.login(credentialWithRealm, function(err, accessToken) {
          assertGoodToken(accessToken, user1);

          done();
        });
      });

      it('rejects a user by with realm in phone if realmDelimiter is not set',
        function(done) {
          User.login(credentialRealmInPhone, function(err, accessToken) {
            assert(err);
            assert.equal(err.code, 'REALM_REQUIRED');

            done();
          });
        });
    });
  });

  describe('User.logout', function() {
    it('Logout a user by providing the current accessToken id (using node)', function(done) {
      login(logout);

      function login(fn) {
        User.login(validCredentials, fn);
      }

      function logout(err, accessToken) {
        User.logout(accessToken.id, verify(accessToken.id, done));
      }
    });

    it('Logout a user by providing the current accessToken id (using node) - promise variant',
      function(done) {
        login(logout);

        function login(fn) {
          User.login(validCredentials, fn);
        }

        function logout(err, accessToken) {
          User.logout(accessToken.id)
            .then(function() {
              verify(accessToken.id, done);
            })
            .catch(done(err));
        }
      });

    it('Logout a user by providing the current accessToken id (over rest)', function(done) {
      login(logout);
      function login(fn) {
        request(app)
          .post('/test-users/login')
          .expect('Content-Type', /json/)
          .expect(200)
          .send(validCredentials)
          .end(function(err, res) {
            if (err) return done(err);

            var accessToken = res.body;
            assertGoodToken(accessToken, validCredentialsUser);

            fn(null, accessToken.id);
          });
      }

      function logout(err, token) {
        request(app)
          .post('/test-users/logout')
          .set('Authorization', token)
          .expect(204)
          .end(verify(token, done));
      }
    });

    it('fails when accessToken is not provided', function(done) {
      User.logout(undefined, function(err) {
        expect(err).to.have.property('message');
        expect(err).to.have.property('statusCode', 401);
        done();
      });
    });

    it('fails when accessToken is not found', function(done) {
      User.logout('expired-access-token', function(err) {
        expect(err).to.have.property('message');
        expect(err).to.have.property('statusCode', 401);
        done();
      });
    });

    function verify(token, done) {
      assert(token);

      return function(err) {
        if (err) return done(err);

        AccessToken.findById(token, function(err, accessToken) {
          assert(!accessToken, 'accessToken should not exist after logging out');

          done(err);
        });
      };
    }
  });

  describe('user.hasPassword(plain, fn)', function() {
    it('Determine if the password matches the stored password', function(done) {
      var u = new User({username: 'foo', password: 'bar'});
      u.hasPassword('bar', function(err, isMatch) {
        assert(isMatch, 'password doesnt match');

        done();
      });
    });

    it('Determine if the password matches the stored password - promise variant', function(done) {
      var u = new User({username: 'foo', password: 'bar'});
      u.hasPassword('bar')
        .then(function(isMatch) {
          assert(isMatch, 'password doesnt match');

          done();
        })
        .catch(function(err) {
          done(err);
        });
    });

    it('should match a password when saved', function(done) {
      var u = new User({username: 'a', password: 'b', phone: '(817) 569-8920'});

      u.save(function(err, user) {
        User.findById(user.pk, function(err, uu) {
          uu.hasPassword('b', function(err, isMatch) {
            assert(isMatch);

            done();
          });
        });
      });
    });

    it('should match a password after it is changed', function(done) {
      User.create({phone: '(817) 569-8956', username: 'bat', password: 'baz'}, function(err, user) {
        User.findById(user.pk, function(err, foundUser) {
          assert(foundUser);
          foundUser.hasPassword('baz', function(err, isMatch) {
            assert(isMatch);
            foundUser.password = 'baz2';
            foundUser.save(function(err, updatedUser) {
              updatedUser.hasPassword('baz2', function(err, isMatch) {
                assert(isMatch);
                User.findById(user.pk, function(err, uu) {
                  uu.hasPassword('baz2', function(err, isMatch) {
                    assert(isMatch);

                    done();
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  describe('User.changePassword()', () => {
    let userId, currentPassword;
    beforeEach(givenUserIdAndPassword);

    it('changes the password - callback-style', done => {
      User.changePassword(userId, currentPassword, 'new password', (err) => {
        if (err) return done(err);
        expect(arguments.length, 'changePassword callback arguments length')
          .to.be.at.most(1);

        User.findById(userId, (err, user) => {
          if (err) return done(err);
          user.hasPassword('new password', (err, isMatch) => {
            if (err) return done(err);
            expect(isMatch, 'user has new password').to.be.true();
            done();
          });
        });
      });
    });

    it('changes the password - Promise-style', () => {
      return User.changePassword(userId, currentPassword, 'new password')
        .then(() => {
          expect(arguments.length, 'changePassword promise resolution')
            .to.equal(0);
          return User.findById(userId);
        })
        .then(user => {
          return user.hasPassword('new password');
        })
        .then(isMatch => {
          expect(isMatch, 'user has new password').to.be.true();
        });
    });

    it('changes the password - instance method', () => {
      validCredentialsUser.changePassword(currentPassword, 'new password')
        .then(() => {
          expect(arguments.length, 'changePassword promise resolution')
            .to.equal(0);
          return User.findById(userId);
        })
        .then(user => {
          return user.hasPassword('new password');
        })
        .then(isMatch => {
          expect(isMatch, 'user has new password').to.be.true();
        });
    });

    it('fails when current password does not match', () => {
      return User.changePassword(userId, 'bad password', 'new password').then(
        success => { throw new Error('changePassword should have failed'); },
        err => {
          // workaround for chai problem
          //   object tested must be an array, an object,
          //   or a string, but error given
          const props = Object.assign({}, err);
          expect(props).to.contain({
            code: 'INVALID_PASSWORD',
            statusCode: 400,
          });
        });
    });

    it('fails with 401 for unknown user id', () => {
      return User.changePassword('unknown-id', 'pass', 'pass').then(
        success => { throw new Error('changePassword should have failed'); },
        err => {
          // workaround for chai problem
          //   object tested must be an array, an object, or a string,
          //   but error given
          const props = Object.assign({}, err);
          expect(props).to.contain({
            code: 'USER_NOT_FOUND',
            statusCode: 401,
          });
        });
    });

    it('forwards the "options" argument', () => {
      const options = {testFlag: true};
      const observedOptions = [];

      saveObservedOptionsForHook('access');
      saveObservedOptionsForHook('before save');

      return User.changePassword(userId, currentPassword, 'new', options)
        .then(() => expect(observedOptions).to.eql([
          // findById
          {hook: 'access', testFlag: true},

          // "before save" hook prepareForTokenInvalidation
          {hook: 'access', setPassword: true, testFlag: true},

          // updateAttributes
          {hook: 'before save', setPassword: true, testFlag: true},

          // validate uniqueness of User.phone
          // {hook: 'access', setPassword: true, testFlag: true},
        ]));

      function saveObservedOptionsForHook(name) {
        User.observe(name, (ctx, next) => {
          observedOptions.push(Object.assign({hook: name}, ctx.options));
          next();
        });
      }
    });

    function givenUserIdAndPassword() {
      userId = validCredentialsUser.id;
      currentPassword = validCredentials.password;
    }
  });

  describe('User.setPassword()', () => {
    let userId;
    beforeEach(givenUserId);

    it('changes the password - callback-style', done => {
      User.setPassword(userId, 'new password', (err) => {
        if (err) return done(err);
        expect(arguments.length, 'changePassword callback arguments length')
          .to.be.at.most(1);

        User.findById(userId, (err, user) => {
          if (err) return done(err);
          user.hasPassword('new password', (err, isMatch) => {
            if (err) return done(err);
            expect(isMatch, 'user has new password').to.be.true();
            done();
          });
        });
      });
    });

    it('changes the password - Promise-style', () => {
      return User.setPassword(userId, 'new password')
        .then(() => {
          expect(arguments.length, 'changePassword promise resolution')
            .to.equal(0);
          return User.findById(userId);
        })
        .then(user => {
          return user.hasPassword('new password');
        })
        .then(isMatch => {
          expect(isMatch, 'user has new password').to.be.true();
        });
    });

    it('fails with 401 for unknown users', () => {
      return User.setPassword('unknown-id', 'pass').then(
        success => { throw new Error('setPassword should have failed'); },
        err => {
          // workaround for chai problem
          //   object tested must be an array, an object, or a string,
          //   but error given
          const props = Object.assign({}, err);
          expect(props).to.contain({
            code: 'USER_NOT_FOUND',
            statusCode: 401,
          });
        });
    });

    it('forwards the "options" argument', () => {
      const options = {testFlag: true};
      const observedOptions = [];

      saveObservedOptionsForHook('access');
      saveObservedOptionsForHook('before save');

      return User.setPassword(userId, 'new', options)
        .then(() => expect(observedOptions).to.eql([
          // findById
          {hook: 'access', testFlag: true},

          // "before save" hook prepareForTokenInvalidation
          {hook: 'access', setPassword: true, testFlag: true},

          // updateAttributes
          {hook: 'before save', setPassword: true, testFlag: true},

          // validate uniqueness of User.phone
          // {hook: 'access', setPassword: true, testFlag: true},
        ]));

      function saveObservedOptionsForHook(name) {
        User.observe(name, (ctx, next) => {
          observedOptions.push(Object.assign({hook: name}, ctx.options));
          next();
        });
      }
    });

    function givenUserId() {
      userId = validCredentialsUser.id;
    }
  });

  describe('Identity verification', function() {
    describe('user.verify(verifyOptions, options, cb)', function() {
      const ctxOptions = {testFlag: true};
      let verifyOptions;

      beforeEach(function() {
        // reset verifyOptions before each test
        verifyOptions = {
          type: 'phone',
          from: '(817) 569-8923',
          to: '(817) 569-8920',
        };
      });

      it('verifies a user\'s phone address', function(done) {
        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          user.verify(verifyOptions, function(err, result) {
            assert(result.phone);
            assert(result.phone.response);
            assert(result.token);
            var msg = result.phone.response.toString('utf-8');
            assert(~msg.indexOf('is your authentication code'));

            done();
          });
        });

        request(app)
          .post('/test-users')
          .expect('Content-Type', /json/)
          .expect(200)
          .send({phone: '(817) 569-8920', password: 'bar'})
          .end(function(err, res) {
            if (err) return done(err);
          });
      });

      it('verifies a user\'s phone address - promise variant', function(done) {
        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          user.verify(verifyOptions)
            .then(function(result) {
              assert(result.phone);
              assert(result.phone.response);
              assert(result.token);
              var msg = result.phone.response.toString('utf-8');
              assert(~msg.indexOf('is your authentication code'));

              done();
            })
            .catch(function(err) {
              done(err);
            });
        });

        request(app)
          .post('/test-users')
          .send({phone: '(817) 569-8920', password: 'bar'})
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(err, res) {
            if (err) return done(err);
          });
      });

      it('verifies a user\'s phone address with custom header', function(done) {
        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          verifyOptions.headers = {'message-id': 'custom-header-value'};

          user.verify(verifyOptions, function(err, result) {
            assert(result.phone);
            assert.equal(result.phone.messageId, 'custom-header-value');

            done();
          });
        });

        request(app)
          .post('/test-users')
          .expect('Content-Type', /json/)
          .expect(200)
          .send({phone: '(817) 569-8920', password: 'bar'})
          .end(function(err, res) {
            if (err) return done(err);
          });
      });

      it('verifies a user\'s phone address with custom template function', function(done) {
        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          verifyOptions.templateFn = function(verifyOptions, cb) {
            cb(null, 'custom template  - verify url: ' + verifyOptions.verifyHref);
          };

          user.verify(verifyOptions, function(err, result) {
            assert(result.phone);
            assert(result.phone.response);
            assert(result.token);
            var msg = result.phone.response.toString('utf-8');
            assert(~msg.indexOf('custom template'));

            done();
          });
        });

        request(app)
          .post('/test-users')
          .expect('Content-Type', /json/)
          .expect(200)
          .send({phone: '(817) 569-8920', password: 'bar'})
          .end(function(err, res) {
            if (err) return done(err);
          });
      });

      xit('converts uid value to string', function(done) {
        const idString = '58be263abc88dd483956030a';
        let actualVerifyHref;

        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          verifyOptions.templateFn = function(verifyOptions, cb) {
            actualVerifyHref = verifyOptions.verifyHref;
            cb(null, 'dummy body');
          };

          // replace the string id with an object
          // TODO: find a better way to do this
          Object.defineProperty(user, 'pk', {
            get: function() { return this.__data.pk; },
            set: function(value) { this.__data.pk = value; },
          });
          user.pk = {toString: function() { return idString; }};

          user.verify(verifyOptions, function(err, result) {
            expect(result.uid).to.exist().and.be.an('object');
            expect(result.uid.toString()).to.equal(idString);
            const parsed = url.parse(actualVerifyHref, true);
            expect(parsed.query.uid, 'uid query field').to.eql(idString);
            done();
          });
        });

        request(app)
          .post('/test-users')
          .expect('Content-Type', /json/)
          .expect(200)
          .send({phone: '(817) 569-8920', password: 'bar', pk: idString})
          .end(function(err, res) {
            if (err) return done(err);
          });
      });

      it('fails if custom token generator returns error', function(done) {
        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          verifyOptions.generateVerificationToken = function(user, cb) {
            // let's ensure async execution works on this one
            process.nextTick(function() {
              cb(new Error('Fake error'));
            });
          };

          user.verify(verifyOptions, function(err, result) {
            assert(err);
            assert.equal(err.message, 'Fake error');
            assert.equal(result, undefined);

            done();
          });
        });

        request(app)
          .post('/test-users')
          .expect('Content-Type', /json/)
          .expect(200)
          .send({phone: '(817) 569-8920', password: 'bar'})
          .end(function(err, res) {
            if (err) return done(err);
          });
      });

      it('hides verification tokens from user JSON', function(done) {
        var user = new User({
          phone: '(817) 569-8920',
          password: 'bar',
          verificationToken: 'a-token',
        });
        var data = user.toJSON();
        assert(!('verificationToken' in data));

        done();
      });

      it('verifies that verifyOptions.templateFn receives verifyOptions.verificationToken',
        function() {
          let actualVerificationToken;

          Object.assign(verifyOptions, {
            redirect: '#/some-path?a=1&b=2',
            templateFn: (verifyOptions, cb) => {
              actualVerificationToken = verifyOptions.verificationToken;
              cb(null, 'dummy body');
            },
            to: user.phoneNumbers[0].phone,
          });

          return user.verify(verifyOptions)
            .then(() => actualVerificationToken)
            .then(token => {
              expect(token).to.exist();
            });
        });

      xit('forwards the "options" argument to user.save() ' +
        'when adding verification token', function() {
        let onBeforeSaveCtx = {};

        // before save operation hook to capture remote ctx when saving
        // verification token in user instance
        User.observe('before save', function(ctx, next) {
          onBeforeSaveCtx = ctx || {};
          next();
        });

        verifyOptions.to = user.phoneNumbers[0].phone;

        return user.verify(verifyOptions, ctxOptions)
          .then(() => {
            // not checking equality since other properties are added by user.save()
            expect(onBeforeSaveCtx.options).to.contain({testFlag: true});
          });
      });

      it('forwards the "options" argument to a custom templateFn function', function() {
        let templateFnOptions;

        // custom templateFn function accepting the options argument
        verifyOptions.templateFn = (verifyOptions, options, cb) => {
          templateFnOptions = options;
          cb(null, 'dummy body');
        };
        verifyOptions.to = user.phoneNumbers[0].phone;

        return user.verify(verifyOptions, ctxOptions)
          .then(() => {
            // not checking equality since other properties are added by user.save()
            expect(templateFnOptions).to.contain({testFlag: true});
          });
      });

      it('forwards the "options" argment to a custom token generator function', function() {
        let generateTokenOptions;

        // custom generateVerificationToken function accepting the options argument
        verifyOptions.generateVerificationToken = (user, options, cb) => {
          generateTokenOptions = options;
          cb(null, 'dummy token');
        };
        verifyOptions.to = user.phoneNumbers[0].phone;

        return user.verify(verifyOptions, ctxOptions)
          .then(() => {
            // not checking equality since other properties are added by user.save()
            expect(generateTokenOptions).to.contain({testFlag: true});
          });
      });

      it('forwards the "options" argument to a custom phoner function', function() {
        let phonerOptions;

        // custom phoner function accepting the options argument
        const phoner = function() {};
        phoner.send = function(verifyOptions, options, cb) {
          phonerOptions = options;
          cb(null, 'dummy result');
        };
        verifyOptions.phoner = phoner;
        verifyOptions.to = user.phoneNumbers[0].phone;

        return user.verify(verifyOptions, ctxOptions)
          .then(() => {
            // not checking equality since other properties are added by user.save()
            expect(phonerOptions).to.contain({testFlag: true});
          });
      });

      function givenUser() {
        return User.create({phone: '(817) 569-8920', password: 'pass'})
          .then(u => user = u);
      }

      it('is called over REST method /User/:id/verify', function() {
        return User.create({phone: '(817) 569-8920', password: 'bar'})
          .then(user => {
            return request(app)
              .post('/test-users/' + user.pk + '/verify')
              .expect('Content-Type', /json/)
              // we already tested before that User.verify(id) works correctly
              // having the remote method returning 204 is enough to make sure
              // User.verify() was called successfully
              .expect(204);
          });
      });

      it('fails over REST method /User/:id/verify with invalid user id', function() {
        return request(app)
          .post('/test-users/' + 'invalid-id' + '/verify')
          .expect('Content-Type', /json/)
          .expect(404);
      });
    });

    describe('User.confirm(options, fn)', function() {
      var verifyOptions;

      function testConfirm(testFunc, done) {
        User.afterRemote('create', function(ctx, user, next) {
          assert(user, 'afterRemote should include result');

          verifyOptions = {
            type: 'phone',
            to: user.phoneNumbers[0].phone,
            from: '(817) 569-8998',
            redirect: 'http://foo.com/bar',
            protocol: ctx.req.protocol,
            host: ctx.req.get('host'),
          };

          user.verify(verifyOptions, function(err, result) {
            if (err) return done(err);
            testFunc(result, done);
          });
        });

        request(app)
          .post('/test-users')
          .expect('Content-Type', /json/)
          .expect(302)
          .send({phone: '(817) 569-8920', password: 'bar'})
          .end(function(err, res) {
            if (err) return done(err);
          });
      }

      it('Confirm a user verification', function(done) {
        testConfirm(function(result, done) {
          request(app)
            .get('/test-users/confirm?uid=' + (result.uid) +
              '&token=' + encodeURIComponent(result.token) +
              '&redirect=' + encodeURIComponent(verifyOptions.redirect))
            .expect(302)
            .end(function(err, res) {
              if (err) return done(err);

              done();
            });
        }, done);
      });

      it('sets verificationToken to null after confirmation', function(done) {
        testConfirm(function(result, done) {
          User.confirm(result.uid, result.token, false, function(err) {
            if (err) return done(err);

            // Verify by loading user data stored in the datasource
            User.findById(result.uid, function(err, user) {
              if (err) return done(err);
              expect(user.phoneNumbers[0]).to.have.property('verificationToken', null);
              done();
            });
          });
        }, done);
      });

      it('Should report 302 when redirect url is set', function(done) {
        testConfirm(function(result, done) {
          request(app)
            .get('/test-users/confirm?uid=' + (result.uid) +
              '&token=' + encodeURIComponent(result.token) +
              '&redirect=http://foo.com/bar')
            .expect(302)
            .expect('Location', 'http://foo.com/bar')
            .end(done);
        }, done);
      });

      it('Should report 204 when redirect url is not set', function(done) {
        testConfirm(function(result, done) {
          request(app)
            .get('/test-users/confirm?uid=' + (result.uid) +
              '&token=' + encodeURIComponent(result.token))
            .expect(204)
            .end(done);
        }, done);
      });

      it('Report error for invalid user id during verification', function(done) {
        testConfirm(function(result, done) {
          request(app)
            .get('/test-users/confirm?uid=' + (result.uid + '_invalid') +
               '&token=' + encodeURIComponent(result.token) +
               '&redirect=' + encodeURIComponent(verifyOptions.redirect))
            .expect(404)
            .end(function(err, res) {
              if (err) return done(err);

              var errorResponse = res.body.error;
              assert(errorResponse);
              assert.equal(errorResponse.code, 'USER_NOT_FOUND');

              done();
            });
        }, done);
      });

      it('Report error for invalid token during verification', function(done) {
        testConfirm(function(result, done) {
          request(app)
            .get('/test-users/confirm?uid=' + result.uid +
              '&token=' + encodeURIComponent(result.token) + '_invalid' +
              '&redirect=' + encodeURIComponent(verifyOptions.redirect))
            .expect(400)
            .end(function(err, res) {
              if (err) return done(err);

              var errorResponse = res.body.error;
              assert(errorResponse);
              assert.equal(errorResponse.code, 'INVALID_TOKEN');

              done();
            });
        }, done);
      });
    });
  });

  describe('Password Reset', function() {
    describe('User.resetPassword(options, cb)', function() {
      var options = {
        phone: '(817) 569-8900',
        redirect: 'http://foobar.com/reset-password',
      };

      xit('Requires phone address to reset password', function(done) {
        User.resetPassword({ }, function(err) {
          assert(err);
          assert.equal(err.code, 'EMAIL_NOT_FOUND');

          done();
        });
      });

      xit('Requires phone address to reset password - promise variant', function(done) {
        User.resetPassword({ })
          .then(function() {
            throw new Error('Error should NOT be thrown');
          })
          .catch(function(err) {
            assert(err);
            assert.equal(err.code, 'EMAIL_NOT_FOUND');

            done();
          });
      });

      it('Reports when phone is not found', function(done) {
        User.resetPassword({phone: '(817) 569-8999'}, function(err) {
          assert(err);
          assert.equal(err.code, 'EMAIL_NOT_FOUND');
          assert.equal(err.statusCode, 404);

          done();
        });
      });

      it('Checks that options exist', function(done) {
        var calledBack = false;

        User.resetPassword(options, function() {
          calledBack = true;
        });

        User.once('resetPasswordRequest', function(info) {
          assert(info.options);
          assert.equal(info.options, options);
          assert(calledBack);

          done();
        });
      });

      it('Creates a temp accessToken to allow a user to change password', function(done) {
        var calledBack = false;

        User.resetPassword({
          phone: options.phone,
        }, function() {
          calledBack = true;
        });

        User.once('resetPasswordRequest', function(info) {
          assert(info.phone);
          assert(info.accessToken);
          assert(info.accessToken.id);
          assert.equal(info.accessToken.ttl / 60, 15);
          assert(calledBack);
          info.accessToken.user(function(err, user) {
            if (err) return done(err);

            assert.equal(user.phoneNumbers[0].phone, options.phone);

            done();
          });
        });
      });

      it('calls createAccessToken() to create the token', function(done) {
        User.prototype.createAccessToken = function(ttl, cb) {
          cb(null, new AccessToken({id: 'custom-token'}));
        };

        User.resetPassword({phone: options.phone}, function() {});

        User.once('resetPasswordRequest', function(info) {
          expect(info.accessToken.id).to.equal('custom-token');
          done();
        });
      });

      it('Password reset over REST rejected without phone address', function(done) {
        request(app)
          .post('/test-users/reset')
          .expect('Content-Type', /json/)
          .expect(404)
          .send({ })
          .end(function(err, res) {
            if (err) return done(err);

            var errorResponse = res.body.error;
            assert(errorResponse);
            assert.equal(errorResponse.code, 'EMAIL_OR_PHONE_REQUIRED');

            done();
          });
      });

      it('Password reset over REST requires phone address', function(done) {
        request(app)
          .post('/test-users/reset')
          .expect('Content-Type', /json/)
          .expect(204)
          .send({phone: options.phone})
          .end(function(err, res) {
            if (err) return done(err);

            assert.deepEqual(res.body, '');

            done();
          });
      });

      it('creates token that allows patching User with new password', () => {
        return triggerPasswordReset(options.phone)
          .then(info => {
            // Make a REST request to change the password
            return request(app)
              .patch(`/test-users/${info.user.id}`)
              .set('Authorization', info.accessToken.id)
              .send({password: 'new-pass'})
              .expect(200);
          })
          .then(() => {
            // Call login to verify the password was changed
            const credentials = {phone: options.phone, password: 'new-pass'};
            return User.login(credentials);
          });
      });

      it('creates token that allows calling other endpoints too', () => {
        // Setup a test method that can be executed by $owner only
        User.prototype.testMethod = function(cb) { cb(null, 'ok'); };
        User.remoteMethod('prototype.testMethod', {
          returns: {arg: 'status', type: 'string'},
          http: {verb: 'get', path: '/test'},
        });
        User.settings.acls.push({
          principalType: 'ROLE',
          principalId: '$owner',
          permission: 'ALLOW',
          property: 'testMethod',
        });

        return triggerPasswordReset(options.phone)
          .then(info => request(app)
            .get(`/test-users/${info.user.id}/test`)
            .set('Authorization', info.accessToken.id)
            .expect(200));
      });

      describe('User.resetPassword(options, cb) requiring realm', function() {
        var realmUser;

        beforeEach(function(done) {
          User.create(validCredentialsWithRealm, function(err, u) {
            if (err) return done(err);

            realmUser = u;
            done();
          });
        });

        it('Reports when phone is not found in realm', function(done) {
          User.resetPassword({
            phone: realmUser.phone,
            realm: 'unknown',
          }, function(err) {
            assert(err);
            assert.equal(err.code, 'EMAIL_OR_PHONE_REQUIRED');
            assert.equal(err.statusCode, 404);

            done();
          });
        });

        xit('Creates a temp accessToken to allow user in realm to change password', function(done) {
          var calledBack = false;

          User.resetPassword({
            phone: realmUser.phone,
            realm: realmUser.realm,
          }, function() {
            calledBack = true;
          });

          User.once('resetPasswordRequest', function(info) {
            assert(info.phone);
            assert(info.accessToken);
            assert(info.accessToken.id);
            assert.equal(info.accessToken.ttl / 60, 15);
            assert(calledBack);
            info.accessToken.user(function(err, user) {
              if (err) return done(err);

              assert.equal(user.phoneNumbers[0].mail, realmUser.phone);

              done();
            });
          });
        });
      });
    });
  });

  describe('AccessToken (session) invalidation', function() {
    var user, originalUserToken1, originalUserToken2, newUserCreated;
    var currentPhoneCredentials = {phone: '(817) 569-9720', password: 'bar'};
    var updatedPhoneCredentials = {phone: '(817) 569-9920', password: 'bar'};
    var newUserCred = {phone: '(817) 569-9571', password: 'newpass'};

    beforeEach('create user then login', function createAndLogin(done) {
      async.series([
        function createUserWithOriginalPhone(next) {
          User.create(currentPhoneCredentials, function(err, userCreated) {
            if (err) return next(err);
            user = userCreated;
            next();
          });
        },
        function firstLoginWithOriginalPhone(next) {
          User.login(currentPhoneCredentials, function(err, accessToken1) {
            if (err) return next(err);
            assert(accessToken1.userId);
            originalUserToken1 = accessToken1;
            next();
          });
        },
        function secondLoginWithOriginalPhone(next) {
          User.login(currentPhoneCredentials, function(err, accessToken2) {
            if (err) return next(err);
            assert(accessToken2.userId);
            originalUserToken2 = accessToken2;
            next();
          });
        },
      ], done);
    });

    it('invalidates sessions when phone is changed using `updateAttributes`', function(done) {
      user.updateAttributes(
        {phone: updatedPhoneCredentials.phone},
        function(err, userInstance) {
          if (err) return done(err);
          assertNoAccessTokens(done);
        });
    });

    xit('invalidates sessions after `replaceAttributes`', function(done) {
      // The way how the invalidation is implemented now, all sessions
      // are invalidated on a full replace
      user.replaceAttributes(currentPhoneCredentials, function(err, userInstance) {
        if (err) return done(err);
        assertNoAccessTokens(done);
      });
    });

    it('invalidates sessions when phone is changed using `updateOrCreate`', function(done) {
      User.updateOrCreate({
        pk: user.pk,
        phone: updatedPhoneCredentials.phone,
      }, function(err, userInstance) {
        if (err) return done(err);
        assertNoAccessTokens(done);
      });
    });

    xit('invalidates sessions after `replaceById`', function(done) {
      // The way how the invalidation is implemented now, all sessions
      // are invalidated on a full replace
      User.replaceById(user.pk, currentPhoneCredentials, function(err, userInstance) {
        if (err) return done(err);
        assertNoAccessTokens(done);
      });
    });

    xit('invalidates sessions after `replaceOrCreate`', function(done) {
      // The way how the invalidation is implemented now, all sessions
      // are invalidated on a full replace
      User.replaceOrCreate({
        pk: user.pk,
        phone: currentPhoneCredentials.phone,
        password: currentPhoneCredentials.password,
      }, function(err, userInstance) {
        if (err) return done(err);
        assertNoAccessTokens(done);
      });
    });

    it('keeps sessions AS IS if firstName is added using `updateAttributes`', function(done) {
      user.updateAttributes({'firstName': 'Janny'}, function(err, userInstance) {
        if (err) return done(err);
        assertPreservedTokens(done);
      });
    });

    it('keeps sessions AS IS when calling save() with no changes', function(done) {
      user.save(function(err) {
        if (err) return done(err);
        assertPreservedTokens(done);
      });
    });

    it('keeps sessions AS IS if firstName is added using `updateOrCreate`', function(done) {
      User.updateOrCreate({
        pk: user.pk,
        firstName: 'Loay',
        phone: currentPhoneCredentials.phone,
      }, function(err, userInstance) {
        if (err) return done(err);
        assertPreservedTokens(done);
      });
    });

    it('keeps sessions AS IS if a new user is created using `create`', function(done) {
      async.series([
        function(next) {
          User.create(newUserCred, function(err, newUserInstance) {
            if (err) return done(err);
            newUserCreated = newUserInstance;
            next();
          });
        },
        function(next) {
          User.login(newUserCred, function(err, newAccessToken) {
            if (err) return done(err);
            assert(newAccessToken.id);
            assertPreservedTokens(next);
          });
        },
      ], done);
    });

    it('keeps sessions AS IS if a new user is created using `updateOrCreate`', function(done) {
      async.series([
        function(next) {
          User.create(newUserCred, function(err, newUserInstance2) {
            if (err) return done(err);
            newUserCreated = newUserInstance2;
            next();
          });
        },
        function(next) {
          User.login(newUserCred, function(err, newAccessToken2) {
            if (err) return done(err);
            assert(newAccessToken2.id);
            assertPreservedTokens(next);
          });
        },
      ], done);
    });

    it('keeps sessions AS IS if non-phone property is changed using updateAll', function(done) {
      var userPartial;
      async.series([
        function createPartialUser(next) {
          User.create(
            {phone: '(817) 569-8972', password: 'pass1', age: 25},
            function(err, partialInstance) {
              if (err) return next(err);
              userPartial = partialInstance;
              next();
            });
        },
        function loginPartiallUser(next) {
          User.login({phone: '(817) 569-8972', password: 'pass1'}, function(err, ats) {
            if (err) return next(err);
            next();
          });
        },
        function updatePartialUser(next) {
          User.updateAll(
            {pk: userPartial.pk},
            {age: userPartial.age + 1},
            function(err, info) {
              if (err) return next(err);
              next();
            });
        },
        function verifyTokensOfPartialUser(next) {
          AccessToken.find({where: {userId: userPartial.pk}}, function(err, tokens1) {
            if (err) return next(err);
            expect(tokens1.length).to.equal(1);
            next();
          });
        },
      ], done);
    });

    it('preserves other users\' sessions if their phone is  untouched', function(done) {
      var user1, user2, user3;
      async.series([
        function(next) {
          User.create({phone: '(817) 569-8920', password: 'u1pass'}, function(err, u1) {
            if (err) return done(err);
            User.create({phone: '(817) 569-8922', password: 'u2pass'}, function(err, u2) {
              if (err) return done(err);
              User.create({phone: '(817) 569-8923', password: 'u3pass'}, function(err, u3) {
                if (err) return done(err);
                user1 = u1;
                user2 = u2;
                user3 = u3;
                next();
              });
            });
          });
        },
        function(next) {
          User.login(
            {phone: '(817) 569-8920', password: 'u1pass'},
            function(err, accessToken1) {
              if (err) return next(err);
              User.login(
                {phone: '(817) 569-8922', password: 'u2pass'},
                function(err, accessToken2) {
                  if (err) return next(err);
                  User.login({phone: '(817) 569-8923', password: 'u3pass'},
                    function(err, accessToken3) {
                      if (err) return next(err);
                      next();
                    });
                });
            });
        },
        function(next) {
          user2.updateAttribute('phone', '(817) 569-8924', function(err, userInstance) {
            if (err) return next(err);
            assert.equal(userInstance.phone, '(817) 569-8924');
            next();
          });
        },
        function(next) {
          AccessToken.find({where: {userId: user1.pk}}, function(err, tokens1) {
            if (err) return next(err);
            AccessToken.find({where: {userId: user2.pk}}, function(err, tokens2) {
              if (err) return next(err);
              AccessToken.find({where: {userId: user3.pk}}, function(err, tokens3) {
                if (err) return next(err);

                expect(tokens1.length).to.equal(1);
                expect(tokens2.length).to.equal(0);
                expect(tokens3.length).to.equal(1);
                next();
              });
            });
          });
        },
      ], done);
    });

    it('invalidates correct sessions after changing phone using updateAll', function(done) {
      var userSpecial, userNormal;
      async.series([
        function createSpecialUser(next) {
          User.create(
            {phone: '(817) 569-8920', password: 'pass1', name: 'Special'},
            function(err, specialInstance) {
              if (err) return next(err);
              userSpecial = specialInstance;
              next();
            });
        },
        function loginSpecialUser(next) {
          User.login({phone: '(817) 569-8920', password: 'pass1'}, function(err, ats) {
            if (err) return next(err);
            next();
          });
        },
        function updateSpecialUser(next) {
          User.updateAll(
            {name: 'Special'},
            {phone: '(817) 569-8922'}, function(err, info) {
              if (err) return next(err);
              next();
            });
        },
        function verifyTokensOfSpecialUser(next) {
          AccessToken.find({where: {userId: userSpecial.pk}}, function(err, tokens1) {
            if (err) return done(err);
            expect(tokens1.length, 'tokens - special user tokens').to.equal(0);
            next();
          });
        },
        assertPreservedTokens,
      ], done);
    });

    it('invalidates session when password is reset', function(done) {
      user.updateAttribute('password', 'newPass', function(err, user2) {
        if (err) return done(err);
        assertNoAccessTokens(done);
      });
    });

    it('preserves current session', function(done) {
      var options = {accessToken: originalUserToken1};
      user.updateAttribute('phone', '(817) 569-9920', options, function(err) {
        if (err) return done(err);
        AccessToken.find({where: {userId: user.pk}}, function(err, tokens) {
          if (err) return done(err);
          var tokenIds = tokens.map(function(t) { return t.id; });
          expect(tokenIds).to.eql([originalUserToken1.id]);
          done();
        });
      });
    });

    it('forwards the "options" argument', function(done) {
      var options = {testFlag: true};
      var observedOptions = [];

      saveObservedOptionsForHook('access', User);
      saveObservedOptionsForHook('before delete', AccessToken);

      user.updateAttribute('password', 'newPass', options, function(err, updated) {
        if (err) return done(err);

        expect(observedOptions).to.eql([
          // prepareForTokenInvalidation - load current instance data
          {hook: 'access', testFlag: true},

          // validate uniqueness of User.phone
          // {hook: 'access', testFlag: true},

          // _invalidateAccessTokensOfUsers - deleteAll
          {hook: 'before delete', testFlag: true},
        ]);
        done();
      });

      function saveObservedOptionsForHook(name, model) {
        model.observe(name, function(ctx, next) {
          observedOptions.push(extend({hook: name}, ctx.options));
          next();
        });
      }
    });

    it('preserves other user sessions if their password is  untouched', function(done) {
      var user1, user2, user1Token;
      async.series([
        function(next) {
          User.create({phone: '(817) 569-9920', password: 'u1pass'}, function(err, u1) {
            if (err) return done(err);
            User.create({phone: '(817) 569-9922', password: 'u2pass'}, function(err, u2) {
              if (err) return done(err);
              user1 = u1;
              user2 = u2;
              next();
            });
          });
        },
        function(next) {
          User.login({phone: '(817) 569-9920', password: 'u1pass'}, function(err, at1) {
            User.login({phone: '(817) 569-9922', password: 'u2pass'}, function(err, at2) {
              assert(at1.userId);
              assert(at2.userId);
              user1Token = at1.id;
              next();
            });
          });
        },
        function(next) {
          user2.updateAttribute('password', 'newPass', function(err, user2Instance) {
            if (err) return next(err);
            assert(user2Instance);
            next();
          });
        },
        function(next) {
          AccessToken.find({where: {userId: user1.pk}}, function(err, tokens1) {
            if (err) return next(err);
            AccessToken.find({where: {userId: user2.pk}}, function(err, tokens2) {
              if (err) return next(err);
              expect(tokens1.length).to.equal(1);
              expect(tokens2.length).to.equal(0);
              assert.equal(tokens1[0].id, user1Token);
              next();
            });
          });
        },
      ], function(err) {
        done();
      });
    });

    // See https://github.com/strongloop/loopback/issues/3215
    xit('handles subclassed user with no accessToken relation', () => {
      // setup a new LoopBack app, we don't want to use shared models
      app = loopback({localRegistry: true, loadBuiltinModels: true});
      app.set('_verifyAuthModelRelations', false);
      app.set('remoting', {errorHandler: {debug: true, log: false}});
      app.dataSource('db', {connector: 'memory'});
      const User = app.registry.createModel({
        name: 'user',
        base: 'User',
      });
      app.model(User, {dataSource: 'db'});
      app.enableAuth({dataSource: 'db'});
      expect(app.models.User.modelName).to.eql('user');

      return User.create(validCredentials)
        .then(u => {
          u.phone = '(817) 569-8720';
          return u.save();
          // the test passes when save() does not throw any error
        });
    });

    function assertPreservedTokens(done) {
      AccessToken.find({where: {userId: user.pk}}, function(err, tokens) {
        if (err) return done(err);
        var actualIds = tokens.map(function(t) { return t.id; });
        actualIds.sort();
        var expectedIds = [originalUserToken1.id, originalUserToken2.id];
        expectedIds.sort();
        expect(actualIds).to.eql(expectedIds);
        done();
      });
    };

    function assertNoAccessTokens(done) {
      AccessToken.find({where: {userId: user.pk}}, function(err, tokens) {
        if (err) return done(err);
        expect(tokens.length).to.equal(0);
        done();
      });
    }
  });

  describe('Verification after updating phone', function() {
    var NEW_PHONE = '+18175698720';
    var userInstance;

    beforeEach(createOriginalUser);

    it('sets verification to false after phone update if verification is required',
      function(done) {
        User.settings.emailVerificationRequired = true;
        async.series([
          function updateUser(next) {
            var phone = userInstance.phones()[0];
            phone.phone = NEW_PHONE;
            userInstance.phones.set(phone.id, phone, function(err, info) {
              if (err) return next(err);
              assert.equal(info.phone, NEW_PHONE);
              next();
            });
          },
          function findUser(next) {
            User.findById(userInstance.pk, function(err, info) {
              if (err) return next(err);
              assert.equal(info.phoneNumbers[0].phone, NEW_PHONE);
              assert.equal(info.phoneNumbers[0].verified, false);
              next();
            });
          },
        ], done);
      });

    xit('leaves verification as is after phone update if verification is not required',
      function(done) {
        User.settings.emailVerificationRequired = false;
        async.series([
          function updateUser(next) {
            var phone = userInstance.phones()[0];
            phone.phone = NEW_PHONE;
            userInstance.phones.set(phone.id, phone, function(err, info) {
              if (err) return next(err);
              assert.equal(info.phone, NEW_PHONE);
              next();
            });
          },
          function findUser(next) {
            User.findById(userInstance.pk, function(err, info) {
              if (err) return next(err);
              assert.equal(info.phoneNumbers[0].phone, NEW_PHONE);
              assert.equal(info.phoneNumbers[0].verified, true);
              next();
            });
          },
        ], done);
      });

    xit('should not set verification to false after something other than phone is updated',
      function(done) {
        User.settings.emailVerificationRequired = true;
        async.series([
          function updateUser(next) {
            userInstance.updateAttribute('realm', 'test', function(err, info) {
              if (err) return next(err);
              assert.equal(info.realm, 'test');
              next();
            });
          },
          function findUser(next) {
            User.findById(userInstance.pk, function(err, info) {
              if (err) return next(err);
              assert.equal(info.realm, 'test');
              assert.equal(info.phoneNumbers[0].verified, true);
              next();
            });
          },
        ], done);
      });

    function createOriginalUser(done) {
      var userData = {
        phone: '(817) 569-8920',
        password: 'bar',
        phoneVerified: true,
      };
      User.create(userData, function(err, instance) {
        if (err) return done(err);
        userInstance = instance;
        done();
      });
    }
  });

  describe('password reset with/without phone verification', function() {
    xit('allows resetPassword by phone if phone verification is required and done',
      function(done) {
        User.settings.emailVerificationRequired = true;
        var phone = validCredentialsPhoneVerified.phone;

        User.resetPassword({phone: phone}, function(err, info) {
          if (err) return done(err);
          done();
        });
      });

    it('disallows resetPassword by phone if phone verification is required and not done',
      function(done) {
        User.settings.emailVerificationRequired = true;
        var phone = validCredentialsPhone;

        User.resetPassword({phone: phone}, function(err) {
          assert(err);
          assert.equal(err.code, 'RESET_FAILED_PHONE_NOT_VERIFIED');
          assert.equal(err.statusCode, 401);
          done();
        });
      });

    it('allows resetPassword by phone if phone verification is not required',
      function(done) {
        User.settings.emailVerificationRequired = false;
        var phone = validCredentialsPhone;

        User.resetPassword({phone: phone}, function(err) {
          if (err) return done(err);
          done();
        });
      });
  });

  function triggerPasswordReset(phone) {
    return Promise.all([
      User.resetPassword({phone: phone}),
      waitForEvent(User, 'resetPasswordRequest'),
    ])
      .spread((reset, info) => info);
  }
});
