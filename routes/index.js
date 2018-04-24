var express = require('express');
var router = express.Router();
var passport = require('passport');
var db = require('../db');
var tokenStorage = require('../utils/remember-me-token');
var ObjectID = require('mongodb').ObjectID;
var GoogleAuthenticator = require('passport-2fa-totp').GoogeAuthenticator;
var formidable = require('formidable');
var fs = require('fs');
var path = require('path');

var authenticated = function(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.redirect('/');
}

router.get('/', function(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/profile');
  }

  var errors = req.flash('error');
  return res.render('index', {
    errors: errors
  });
});

router.post('/', passport.authenticate('login', {
  failureRedirect: '/',
  failureFlash: true,
  badRequestMessage: 'Invalid username or password.'
}), function(req, res, next) {
  if (!req.body.remember) {
    return res.redirect('/profile');
  }

  // Create remember_me cookie and redirect to /profile page
  tokenStorage.create(req.user, function(err, token) {
    if (err) {
      return next(err);
    }

    res.cookie('remember_me', token, {
      path: '/',
      httpOnly: true,
      maxAge: 604800000
    });
    return res.redirect('/profile');
  });
});

router.get('/register', function(req, res, next) {
  var errors = req.flash('error');
  return res.render('register', {
    errors: errors
  });
});

router.get('/upload', function(req, res, next) {
  var errors = req.flash('error');
  if (req.isAuthenticated()) {
    return res.render('upload', {
      errors: errors
    });
  } else {
    res.redirect('/');
  }
});

router.post('/upload', function(req, res) {
  var form = new formidable.IncomingForm();
  form.parse(req, function(err, fields, files) {
    // `file` is the name of the <input> field of type `file`
    var old_path = files.file.path,
      file_size = files.file.size,
      file_ext = files.file.name.split('.').pop(),
      index = old_path.lastIndexOf('/') + 1,
      file_name = old_path.substr(index),
      new_path = path.join(process.env.PWD, '/uploads/', file_name + '.' + file_ext);

    fs.readFile(old_path, function(err, data) {
      fs.writeFile(new_path, data, function(err) {
        fs.unlink(old_path, function(err) {
          if (err) {
            res.status(500);
            res.json({
              'success': false
            });
          } else {
            res.status(200);
            res.json({
              'success': true
            });
          }
        });
      });
    });
  });
});

router.get('/recoverpassword', function(req, res, next) {
  var errors = req.flash('error');
  return res.render('recoverpassword', {
    errors: errors
  });
});

router.post('/register', passport.authenticate('register', {
  successRedirect: '/setup-2fa',
  failureRedirect: '/register',
  failureFlash: true
}));

router.get('/setup-2fa', authenticated, function(req, res, next) {
  var errors = req.flash('setup-2fa-error');
  var qrInfo = GoogleAuthenticator.register(req.user.username);
  req.session.qr = qrInfo.secret;

  return res.render('setup-2fa', {
    errors: errors,
    qr: qrInfo.qr
  });
});

router.post('/setup-2fa', authenticated, function(req, res, next) {
  if (!req.session.qr) {
    req.flash('setup-2fa-error', 'The Account cannot be registered. Please try again.');
    return res.redirect('/setup-2fa');
  }

  var users = db.get().collection('users');
  users.findOne(new ObjectID(req.user._id), function(err, user) {
    if (err) {
      req.flash('setup-2fa-error', err);
      return res.redirect('/setup-2fa');
    }

    if (!user) {
      // User is not found. It might be removed directly from the database.
      req.logout();
      return res.redirect('/');
    }

    users.update(user, {
      $set: {
        secret: req.session.qr
      }
    }, function(err) {
      if (err) {
        req.flash('setup-2fa-error', err);
        return res.redirect('/setup-2fa');
      }

      res.redirect('/profile');
    });
  });
});

router.get('/profile', authenticated, function(req, res, next) {
  return res.render("profile", {
    user: req.user
  });
});

router.get('/logout', authenticated, function(req, res, next) {
  tokenStorage.logout(req, res, function() {
    req.logout();
    return res.redirect('/');
  });
});

module.exports = router;