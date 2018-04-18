var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

const saltRounds = 10;

mongoose.connect('mongodb://localhost/nodeauth');

var db = mongoose.connection;

// User Schema
var UserSchema = mongoose.Schema({
  fname: {
    type: String,
    index: true
  },
  lname: {
    type: String
  },
  email: {
    type: String
  },
  password: {
    type: String
  }
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.getUserById = function(id, callback) {
  User.findById(id, callback);
}

module.exports.getUserByEmail = function(email, callback) {
  var query = {email: email};
  User.findOne(query, callback);
}

module.exports.comparePassword = function(candidatePassword, hash, callback) {
console.log('It is /');
  bcrypt.compare(candidatePassword, hash, function(err, res) {
    // res == true
    callback(null, res);
  });
}

module.exports.createUser = function(newUser, callback){

  bcrypt.hash(newUser.password, saltRounds, function(err, hash) {

    newUser.password = hash;
    newUser.save(callback);

  });
}
