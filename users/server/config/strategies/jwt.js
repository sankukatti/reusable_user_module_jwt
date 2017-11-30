'use strict';

/**
 * Module dependencies
 */
var path = require('path');
var passport = require('passport');
var passportJWT = require('passport-jwt');
var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;
var config = require(path.resolve('./config/config'));
var mongoose = require('mongoose');


module.exports = function () {

    var opts = {
        'jwtFromRequest': ExtractJwt.fromAuthHeader(),
        'secretOrKey': config.app.jwt_secret
    };
    passport.use(new JwtStrategy(opts, function (jwt_payload, done) {
        var user = jwt_payload.user;
        var mongooseModel = null;
        if (user.roles[0] === 'customer') {
            mongooseModel = mongoose.model('Customer');
        }
        if (user.roles[0] === 'carryr') {
            mongooseModel = mongoose.model('Carryr');
        }
        if (mongooseModel === null) {
            return done('Malformed Token. Incompatible roles', false);
        } else {
            mongooseModel.findOne({ user: user._id }).populate('user').exec(function (error, user) {
                if (error) {
                    return done(error, false);
                } else {
                    if (user) {
                        if (!user.user.verified) {
                            return done(null, false, {
                                message: 'Your Account is not yet verified.'
                            });
                        } else if (user) {
                            return done(null, user);
                        } else {
                            return done(null, false);
                        }
                    } else {
                        return done(null, false);
                    }
                }
            });
        }
    }));
};

