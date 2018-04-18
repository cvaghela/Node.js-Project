var express = require('express');
var router = express.Router();
var multer = require('multer');
var upload = multer({dest: './uploads'});
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.get('/register', function(req, res, next) {
  res.render('register');
});

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.get('/recoverpassword', function(req, res, next) {
  res.render('recoverpassword');
});

router.post('/login', passport.authenticate('local', {failureRedirect:'/users/login'}), function(req, res) {
    console.log('Authentication was called');
    res.redirect('/');

});

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy(function(email, password, done) {
  User.getUserByEmail(email, function(err, user) {
    if (err) { return done(err); }
    if(!user){
console.log('It is /');
      return done(null, false, {message: 'Incorrect Username!'});
    }

    User.comparePassword(password, user.password, function(err, isMatch){
      if(err) return done(err);
      if(isMatch) {
        return done(null, user);
      } else {
console.log('It is /');
        return done(null, false, {message:'Invalid Password!'});
      }
    });
  });
}));

router.post('/register', function(req, res, next) {
  var fname = req.body.fname;
  var lname = req.body.lname;
  var email = req.body.email;
  var password = req.body.password;

  var newUser = User({
    fname: fname,
    lname: lname,
    email: email,
    password: password
  });

  User.createUser(newUser, function(err, user){
    if(err) throw err;
    console.log(user);
  });

  res.location('/users/login');
  res.redirect('/users/login');

});

router.get('/logout', function(req, res) {
  req.logout();
  req.flash('Success', 'You have been successfully logged out!');
  res.redirect('/users/login');
});

module.exports = router;
