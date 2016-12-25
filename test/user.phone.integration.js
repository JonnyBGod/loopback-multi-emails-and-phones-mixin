// Copyright IBM Corp. 2015,2016. All Rights Reserved.
// Node module: loopback
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
var loopback = require('loopback');
var lt = require('./helpers/loopback-testing-helper');
var path = require('path');
var SIMPLE_APP = path.join(__dirname, 'fixtures', 'user-integration-app');
var app = require(path.join(SIMPLE_APP, 'server/server.js'));
var expect = require('./helpers/expect');

describe('users with phones - integration', function() {
  lt.beforeEach.withApp(app);

  before(function(done) {
    app.models.User.destroyAll(function(err) {
      if (err) return done(err);

      app.models.Post.destroyAll(function(err) {
        if (err) return done(err);

        app.models.blog.destroyAll(function(err) {
          if (err) return done(err);

          done();
        });
      });
    });
  });

  describe('sub-user', function() {
    var userId, accessToken;

    it('should create a new user', function(done) {
      var url = '/api/myUsers';

      this.post(url)
        .send({email: 'y@x.com', phone: '+351912345678', password: 'y'})
        .expect(200, function(err, res) {
          if (err) return done(err);

          expect(res.body.id).to.exist();
          userId = res.body.id;

          done();
        });
    });

    it('should log into the user', function(done) {
      var url = '/api/myUsers/login';

      this.post(url)
        .send({phone: '+351912345678', password: 'y'})
        .expect(200, function(err, res) {
          if (err) return done(err);

          expect(res.body.id).to.exist();
          accessToken = res.body.id;

          done();
        });
    });
  });
});
