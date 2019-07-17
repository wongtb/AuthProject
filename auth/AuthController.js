// AuthController.js

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
const config = require('../config'); 
var User = require('../user/User');
var router = express.Router();

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

// register api
router.post('/register', function(req, res){

    var hashedPassword = bcrypt.hashSync(req.body.password, 8);

    User.create({
        name : req.body.name,
        email : req.body.email,
        password : hashedPassword
    },
    
    function (err, user) {
        if (err) return res.status(500).send("There was a problem registering the user.")

        //create a toekn
        var token = jwt.sign({ id: user._id}, config.secret, {
            expiresIn: 86400 // 24hrs;
        });
        res.status(200).send({ auth: true, token: token }); 
    });
})

// decode api
router.get('me', function(req, res) {
    var token = req.headers['x-access-token'];
    if(!token) return res.status(401).send({ auth : false, message: 'No token provided.'});

    jwt.verify(token, config.secret, function(err, decoded){
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

        res.status(200).send(decoded); 
    });
});

// export
module.exports = router; 