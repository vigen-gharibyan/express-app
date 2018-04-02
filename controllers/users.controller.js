var config = require('../config/app.json');
var mongoose = require('mongoose');
var express = require('express');
var passport = require('passport');
var jwt = require('jsonwebtoken');
var router = express.Router();
var userService = require('services/user.service');
var User = require("../models/user");

require('../config/passport')(passport);

// routes
router.post('/authenticate', authenticate);
router.post('/register', register);
router.get('/', passport.authenticate('jwt', {session: false}), getAll);
router.get('/current', getCurrent);
router.put('/:_id', update);
router.delete('/:_id', _delete);

module.exports = router;

function register(req, res) {
    {
        var newUser = new User({
            username: req.body.username || '',
            email: req.body.email || '',
            password: req.body.password || ''
        });
        // save the user
        newUser.save(function (err) {
            if (err) {
                let message = '';

                if (err.code === 11000) {
                    message = 'User already exists'
                } else {
                    if (err.errors) {
                        if (err.errors.username) {
                            message = err.errors.username.message;
                        }
                        if (err.errors.email) {
                            message = err.errors.email.message;
                        }
                        if (err.errors.password) {
                            message = err.errors.password.message;
                        }
                    }
                }

                return res.json({
                    success: false,
                    msg: message
                });
            }
            return res.json({
                success: true,
                msg: 'User registered successfully.'
            });
        });
    }
}

function authenticate(req, res) {
    User.findOne({
        $or: [
            {username: req.body.username},
            {email: req.body.username}
        ]
    }, function (err, user) {
        if (err) {
            let message = '';
            if (err.errors) {
                if (err.errors.username) {
                    message = err.errors.username.message;
                }
                if (err.errors.password) {
                    message = err.errors.password.message;
                }
            }
            return res.json({
                success: false,
                msg: message
            });
        //    throw err;
        }

        if (!user) {
            res.json({
                success: false,
                msg: 'User not found.'
            });
        } else {
            // check if password matches
            user.comparePassword(req.body.password, function (err, isMatch) {
                if (isMatch && !err) {
                    // if user is found and password is right create a token
                    var token = jwt.sign(user.toJSON(), config.secret);
                    // return the information including token as JSON
                    res.json({
                        success: true,
                        token: token
                    });
                } else {
                    res.json({
                        success: false,
                        msg: 'Wrong password.'
                    });
                }
            });
        }
    });
}

function getAll(req, res) {
    var token = getToken(req.headers);
    if (token) {
        User.find(function (err, users) {
            if (err) return next(err);
            res.json(users);
        });
    } else {
        return res.status(403).send({
            success: false,
            msg: 'Unauthorized.'
        });
    }
}

function getCurrent(req, res) {

    /*
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, config.secret, (err, decoded) => {
        const userId = decoded.sub;
        User.findById(userId, (userErr, user) => {
            return res.status(200).json({
                success: true,
                msg: user
            });
        });
    });
    */

    userService.getById(req.user.sub)
        .then(function (user) {
            if (user) {
                res.send(user);
            } else {
                res.sendStatus(404);
            }
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

function update(req, res) {
    userService.update(req.params._id, req.body)
        .then(function () {
            res.json('success');
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

function _delete(req, res) {
    userService.delete(req.params._id)
        .then(function () {
            res.json('success');
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}