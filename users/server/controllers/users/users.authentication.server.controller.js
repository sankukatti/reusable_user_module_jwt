'use strict';

/**
 * Module dependencies
 */
var path = require('path'),
    errorHandler = require(path.resolve('./modules/core/server/controllers/errors.server.controller')),
    mongoose = require('mongoose'),
    passport = require('passport'),
    User = mongoose.model('User');

var config = require(path.resolve('./config/config'));
var jwt = require('jsonwebtoken');

// URLs for which user can't be redirected on signin
/* var noReturnUrls = [
    '/authentication/signin',
    '/authentication/signup'
];*/

/**
 * Signup
 */
exports.signup = function (req, res) {
    // For security measurement we remove the roles from the req.body object
    delete req.body.roles;

    // Init user and add missing fields
    var user = new User(req.body);
    user.provider = 'local';
    user.displayName = user.firstName + ' ' + user.lastName;

    // Then save the user
    user.save(function (err) {
        if (err) {
            return res.status(422).send({
                message: errorHandler.getErrorMessage(err)
            });
        } else {
            // Remove sensitive data before login
            user.password = undefined;
            user.salt = undefined;
            jwtLogin(user.email, req.body.password)
            .then(function (user) {
                res.jsonp(user);
            }, function (error) {
                res.status(error.status).send({ message: error.message });
            });
        }
    });
};

/**
 * Signin after passport authentication
 */
exports.signin = function (req, res, next) {

    if (req.body.email && req.body.password) {
        var email = req.body.email;
        var password = req.body.password;

        User.findOne({ 'email': email }).populate('activities').exec(function (err, user) {
            if (!user) {
                res.status(401).json({ message: 'User not found.' });
            }
            if (user.authenticate(password)) {
                jwtLogin(user.email, req.body.password)
                .then(function (user) {
                    res.jsonp(user);
                }, function (error) {
                    res.status(error.status).send({ message: error.message });
                });
            } else {
                res.status(401).send({ message: 'Email and password does not match.' });
            }
        });

    } else {
        res.status(422).send({ message: 'Both email and password are required to login.' });
    }
};

/**
 * Signout
 */
exports.signout = function (req, res) {
    req.logout();
    res.redirect('/');
};

exports.socialSignupLogin = function (channel) {
    return function (req, res, next) {
        var Channel = getChannelClass(channel);
        var channelObject = new Channel();
        channelObject.getMyProfile('EAACEdEose0cBAMxkO6LVvH4Wi54nslcg5ZAf1mlj3rZAHkxfzHtby4kixIIpXkeD92i2YfSbeSBgsCards6uWuXcNcZAwskSmUj8KBrqGrqiCKZBi2mZBKT7j1imBBFq1T2xJNgoO4Fc5w45dZBZCon3vKHDm2GoKBgdzaJxYcBQhNM4w2V1haQaBH68v681NgGtBIYLxZBjmgZDZD', { id: '', name: '', first_name: '', last_name: '', email: '' })
        .then(function (user) {
            res.send(user);
        }, function (error_message) {
            res.status(401).send(error_message);
        });
    };
};

function getChannelClass(channel) {
    var channelObject;
    var basePath = './modules/core/server/helpers/social_login/';
    switch (channel) {
    case 'facebook':
        channelObject = require(path.resolve(basePath + 'facebook'));
        break;
    case 'google': break;
    case 'linkedin': break;
    }
    return channelObject;
}


/**
 * OAuth provider call
 */
exports.oauthCall = function (strategy, scope) {
    return function (req, res, next) {
        if (req.query && req.query.redirect_to)
            req.session.redirect_to = req.query.redirect_to;

        // Authenticate
        passport.authenticate(strategy, scope)(req, res, next);
    };
};

/**
 * OAuth callback
 */
exports.oauthCallback = function (strategy) {
    return function (req, res, next) {

        // info.redirect_to contains inteded redirect path
        passport.authenticate(strategy, function (err, user, info) {
            if (err) {
                return res.redirect('/authentication/signin?err=' + encodeURIComponent(errorHandler.getErrorMessage(err)));
            }
            if (!user) {
                return res.redirect('/authentication/signin');
            }
            req.login(user, function (err) {
                if (err) {
                    return res.redirect('/authentication/signin');
                }

                return res.redirect(info.redirect_to || '/');
            });
        })(req, res, next);
    };
};

/**
 * Helper function to save or update a OAuth user profile
 */
exports.saveOAuthUserProfile = function (req, providerUserProfile, done) {
    // Setup info object
    var info = {};

    // Set redirection path on session.
    // Do not redirect to a signin or signup page
    if (noReturnUrls.indexOf(req.session.redirect_to) === -1)
        info.redirect_to = req.session.redirect_to;

    if (!req.user) {
        // Define a search query fields
        var searchMainProviderIdentifierField = 'providerData.' + providerUserProfile.providerIdentifierField;
        var searchAdditionalProviderIdentifierField = 'additionalProvidersData.' + providerUserProfile.provider + '.' + providerUserProfile.providerIdentifierField;

        // Define main provider search query
        var mainProviderSearchQuery = {};
        mainProviderSearchQuery.provider = providerUserProfile.provider;
        mainProviderSearchQuery[searchMainProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

        // Define additional provider search query
        var additionalProviderSearchQuery = {};
        additionalProviderSearchQuery[searchAdditionalProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

        // Define a search query to find existing user with current provider profile
        var searchQuery = {
            $or: [mainProviderSearchQuery, additionalProviderSearchQuery]
        };

        User.findOne(searchQuery, function (err, user) {
            if (err) {
                return done(err);
            } else {
                if (!user) {
                    var possibleUsername = providerUserProfile.username || ((providerUserProfile.email) ? providerUserProfile.email.split('@')[0] : '');

                    User.findUniqueUsername(possibleUsername, null, function (availableUsername) {
                        user = new User({
                            firstName: providerUserProfile.firstName,
                            lastName: providerUserProfile.lastName,
                            username: availableUsername,
                            displayName: providerUserProfile.displayName,
                            profileImageURL: providerUserProfile.profileImageURL,
                            provider: providerUserProfile.provider,
                            providerData: providerUserProfile.providerData
                        });

                        // Email intentionally added later to allow defaults (sparse settings) to be applid.
                        // Handles case where no email is supplied.
                        // See comment: https://github.com/meanjs/mean/pull/1495#issuecomment-246090193
                        user.email = providerUserProfile.email;

                        // And save the user
                        user.save(function (err) {
                            return done(err, user, info);
                        });
                    });
                } else {
                    return done(err, user, info);
                }
            }
        });
    } else {
        // User is already logged in, join the provider data to the existing user
        var user = req.user;

        // Check if user exists, is not signed in using this provider, and doesn't have that provider data already configured
        if (user.provider !== providerUserProfile.provider && (!user.additionalProvidersData || !user.additionalProvidersData[providerUserProfile.provider])) {
            // Add the provider data to the additional provider data field
            if (!user.additionalProvidersData) {
                user.additionalProvidersData = {};
            }

            user.additionalProvidersData[providerUserProfile.provider] = providerUserProfile.providerData;

            // Then tell mongoose that we've updated the additionalProvidersData field
            user.markModified('additionalProvidersData');

            // And save the user
            user.save(function (err) {
                return done(err, user, info);
            });
        } else {
            return done(new Error('User is already connected using this provider'), user);
        }
    }
};

/**
 * Remove OAuth provider
 */
exports.removeOAuthProvider = function (req, res, next) {
    var user = req.user;
    var provider = req.query.provider;

    if (!user) {
        return res.status(401).json({
            message: 'User is not authenticated'
        });
    } else if (!provider) {
        return res.status(400).send();
    }

    // Delete the additional provider
    if (user.additionalProvidersData[provider]) {
        delete user.additionalProvidersData[provider];

        // Then tell mongoose that we've updated the additionalProvidersData field
        user.markModified('additionalProvidersData');
    }

    user.save(function (err) {
        if (err) {
            return res.status(422).send({
                message: errorHandler.getErrorMessage(err)
            });
        } else {
            req.login(user, function (err) {
                if (err) {
                    return res.status(400).send(err);
                } else {
                    return res.json(user);
                }
            });
        }
    });
};

function generateJwtToken (user) {
    var secret = config.app.jwt_secret;
    var payload = { id: user._id };
    return jwt.sign(payload, secret);
}

/*
 * Clean up user object
 * */
function cleanUserObject (user) {
    user = user.toObject();
    delete user.password;
    delete user.salt;
    delete user.provider;
    delete user.providerData;
    delete user.additionalProvidersData;
    delete user.resetPasswordToken;
    delete user.resetPasswordExpires;
    delete user.__v;
    delete user.created;
    return user;
}


/*
* JWT Login
* */
function jwtLogin(email, password) {
    console.log(email);
    return new Promise(function (resolve, reject) {
        getUser({ email: email }, '_')
        .then(function (user) {
            if (user.authenticate(password)) {
                var token = generateJwtToken(user);
                return resolve({ message: 'ok', token: token, user: cleanUserObject(user) });
            } else {
                return reject({ status: 401, message: 'Email and password does not match.' });
            }
        }, function (error) {
            return reject({ status: 401, message: error.message });
        });
    });
}

/*
* Get a user
* */
function getUser(queryObject, populateString) {
    return new Promise(function (resolve, reject) {
        User.findOne(queryObject).populate(populateString).exec(function (err, user) {
            if (err) {
                return reject({ message: err });
            } else {
                if (!user) {
                    return reject({ message: 'User not found' });
                } else {
                    return resolve(user);
                }
            }
        });
    });
}
