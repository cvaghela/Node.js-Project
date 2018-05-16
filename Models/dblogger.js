'use strict'

var mongodb = require('mongodb');
var mongoClient = mongodb.MongoClient;
var url = 'mongodb://127.0.0.1:27017/nodeauth';
var logCollection = 'log_event';

/**
 * Module to log events on mongodb DB
 */
var dbLogger = {
  /**
   * Logs event
   * @param path
   * @param type
   * @param callback
   */
  logEvent: function(path, type, callback) {
    mongoClient.connect(url, function(err, db) {
      if (err)
        callback(err);
      else {
        db.collection(logCollection).insert({
          timedate: new Date(),
          path: path,
          type: type
        }, function(err, result) {
          callback(err);
          db.close();
        });
      }
    });
  },
};

module.exports = dbLogger;