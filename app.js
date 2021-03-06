var express = require('express');
var app = express();
var db = require('./db');

app.get('/api', function (req, res) {
    res.status(200).send('API works.');
  });

var UserController = require('./user/UserController');
app.use('/api/users', UserController);

var AuthController = require('./auth/AuthController');
app.use('/api/auth', AuthController); 

module.exports = app;