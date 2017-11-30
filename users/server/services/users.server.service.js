'use strict';

/**
 * Module dependencies
 */
var path = require('path');
var mongoose = require('mongoose');
var User = mongoose.model('User');
var config = require(path.resolve('./config/config'));
var jwt = require('jsonwebtoken');
var async = require('async');
var OTPClass = require(path.resolve('./modules/core/server/helpers/otp'));
var fs = require('fs');
var Handlebars = require('handlebars');
var nodemailer = require('nodemailer');
var smtpTransport = nodemailer.createTransport(config.mailer.options);


/*
 *
 * ###################### REPO FUNCTIONS ##########################
 *
 * */


/*
* CreateUser. Adds a new user record to the database.
* userObject Object An object with properties of a user.
* */
function createUser(userMongooseObject) {
    return new Promise(function (resolve, reject) {
        userMongooseObject.save(function (err) {
            if (err) {
                return reject(err);
            } else {
                // Remove sensitive data
                userMongooseObject.password = undefined;
                userMongooseObject.salt = undefined;
                return resolve(userMongooseObject);
            }
        });
    });
}

function findByEmail(email) {
    return new Promise(function (resolve, reject) {
        User.findOne({ email: email }).exec(function (err, user) {
            if (err) {
                return reject(err);
            } else if (!user) {
                return reject({ code: 'USER_NOT_FOUND' });
            } else {
                return resolve(user);
            }
        });
    });
}

/*
 * Get a user
 * */
function getUser(queryObject) {
    return new Promise(function (resolve, reject) {
        User.findOne(queryObject).exec(function (err, user) {
            if (err) {
                return reject(err);
            } else {
                if (!user) {
                    return reject({ code: 'USER_NOT_FOUND' });
                } else {
                    return resolve(user);
                }
            }
        });
    });
}

/*
* Save user
* */
function saveUser(user) {
    return new Promise(function (resolve, reject) {
        user.save(function (err) {
            if (err) {
                return reject(err);
            } else {
                return resolve(user);
            }
        });
    });
}

/*
*
* ###################### END OF REPO FUNCTIONS ##########################
*
* */


/*
*
* ##################### EXPORT FUNCTIONS #################################
*
* */


function signUp(userObject) {
    return new Promise(function (resolve, reject) {
        // For security measurement we remove the roles from the req.body object
        // delete userObject.roles;

        // Init user and add missing fields
        var user = new User(userObject);
        user.provider = 'local';

        if (userObject.hasOwnProperty('firstName') && userObject.hasOwnProperty('lastName')) {
            user.displayName = user.firstName + ' ' + user.lastName;
        }

        async.waterfall([
            // Generate OTP
            function (done) {
                try {
                    var OTPGenObject = new OTPClass(6);
                    done(false, OTPGenObject.generateOTP());
                } catch (e) {
                    done(e, null);
                }
            },

            // OTP. Assign OTP and Create user
            function (OTP, done) {
                if (OTP === null) {
                    return reject({ code: 'OTP_GEN_ERROR' });
                }
                user.verfOtp = {};
                user.verfOtp.OTP = OTP;
                user.verfOtp.time = new Date();
                findByEmail(user.email)
                .then(function (user) {
                    if (!user.verified) {
                        user.verfOtp = {};
                        user.verfOtp.OTP = OTP;
                        user.verfOtp.time = new Date();
                        user.save(function (err) {
                            done(false, user);
                        });
                    } else {
                        done({ code: 'EMAIL_EXISTS' });
                    }
                }, function (error) {
                    createUser(user)
                    .then(function (user) {
                        done(false, user);
                    }, function (error) {
                        done(error);
                    });
                });
            },

            // Send email with OTP.
            function (user, done) {
                sendOTP(user)
                .then(function (success) {
                    return resolve({ message: 'An email is sent to the registered email address with an OTP. Please use that OTP to activate your account', user: cleanUserObject(user) });
                }, function (error) {
                    done(error);
                });
            }
        ],
        // Handle any error.
        function (error, done) {
            return reject(error);
        });

    });
}

function resendSignUpOTP(email) {
    return new Promise(function (resolve, reject) {
        async.waterfall([
            // Is user not verified?
            function (done) {
                findByEmail(email)
                    .then(function (user) {
                        if (user.verified) {
                            return resolve({ message: 'Account is already vefified. Please login' });
                        } else {
                            done(false, user);
                        }
                    }, function (error) {
                        done(error);
                    });
            },
            // User verified or resend OTP
            function (user, done) {
                var newOTP = null;
                try {
                    var OTPGenObject = new OTPClass(6);
                    newOTP = OTPGenObject.generateOTP();
                } catch (e) {
                    newOTP = null;
                }

                if (newOTP === null) {
                    return reject({ code: 'OTP_GEN_ERROR' });
                }
                user.verfOtp = {};
                user.verfOtp.OTP = newOTP;
                user.verfOtp.time = new Date();
                user.save();
                sendOTP(user)
                .then(function (success) {
                    return resolve({ message: 'The OTP you have used is old. We have sent an updated OTP. Please use it for verification.', user: user });
                }, function (error) {
                    done(error);
                });
            }
        ], function (error, done) {
            return reject(error);
        });
    });
}

function validateEmail(email, otp) {
    return new Promise(function (resolve, reject) {
        async.waterfall([
            // Is user not verified?
            function (done) {
                findByEmail(email)
                .then(function (user) {
                    if (user.verified) {
                        return resolve({ message: 'Account is already vefified. Please login' });
                    } else {
                        done(false, user);
                    }
                }, function (error) {
                    done(error);
                });
            },
            // Does OTP match?
            // Is time difference between OTP generation and use is less than 5 minutes?
            function (user, done) {
                if (user.verfOtp.OTP === otp) {
                    var currentDate = new Date();
                    var otpAgeInMinutes = ((currentDate - user.verfOtp.time) / 1000) / 60;
                    if (otpAgeInMinutes > 5) {
                        done(false, user, true);
                    } else {
                        done(false, user, false);
                    }
                } else {
                    done({ code: 'OTP_MISMATCH' });
                }
            },
            // User verified or resend OTP
            function (user, resendOtp, done) {
                if (resendOtp) {
                    var newOTP = null;
                    try {
                        var OTPGenObject = new OTPClass(6);
                        newOTP = OTPGenObject.generateOTP();
                    } catch (e) {
                        newOTP = null;
                    }

                    if (newOTP === null) {
                        return reject({ code: 'OTP_GEN_ERROR' });
                    }
                    user.verfOtp = {};
                    user.verfOtp.OTP = newOTP;
                    user.verfOtp.time = new Date();
                    user.save();
                    sendOTP(user)
                    .then(function (success) {
                        return resolve({ message: 'The OTP you have used is old. We have send an updated OTP. Please use it for verification.', user: user });
                    }, function (error) {
                        done(error);
                    });
                } else {
                    user.verified = true;
                    user.save(function (error) {
                        return resolve({ message: 'Your account is successfully validated. Please login.', user: user });
                    });
                }
            }
        ], function (error, done) {
            return reject(error);
        });
    });

}

function jwtSignIn(email, password) {
    return new Promise(function (resolve, reject) {
        if (email && password) {
            findByEmail(email)
            .then(function (user) {
                if (user.verified) {
                    if (user.provider === 'local') {
                        if (user.authenticate(password)) {

                            var token = generateJwtToken(user);
                            return resolve({ token: token, user: cleanUserObject(user) });

                        } else {
                            return reject({ code: 'MISMATCH_CREDS' });
                        }
                    } else {
                        return reject({ code: 'MISMATCH_CREDS' });
                    }
                } else {
                    return reject({ code: 'USER_VERIFICATION_PENDING' });
                }
            }, function (error) {
                return reject(error);
            });
        } else {
            return reject({ code: 'LOGIN_MISSING_CREDS' });
        }
    });
}

function socialSignUpLogin(channel, accessToken, role) {
    return new Promise(function (resolve, reject) {
        var Channel = getChannelClass(channel);
        var channelObject = new Channel();
        channelObject.getMyProfile(accessToken, { id: 'id', name: 'displayName', first_name: 'firstName', last_name: 'lastName', email: 'email' })
        .then(function (userDetails) {

            if (userDetails.hasOwnProperty('email')) {
                findByEmail(userDetails.email)
                .then(function (user) {
                    /* Login */
                    var token = generateJwtToken(user);
                    return resolve({ token: token, user: user });
                }, function (error) {
                    /* Create user then login */
                    var user = new User({
                        firstName: userDetails.firstName,
                        lastName: userDetails.lastName,
                        displayName: userDetails.displayName,
                        email: userDetails.email,
                        provider: channel,
                        providerData: userDetails,
                        verified: true,
                        password: userDetails.email,
                        roles: role
                    });
                    createUser(user)
                    .then(function (user) {
                        var token = generateJwtToken(user);
                        return resolve({ token: token, user: user });
                    }, function (error) {
                        return reject(error);
                    });
                });
            } else {
                return reject({ code: 'SOCIAL_EMAIL_MISSING' });
            }
        }, function (error_code) {
            return reject({ code: error_code });
        });
    });
}

function forgotPassword(email) {
    return new Promise(function (resolve, reject) {
        findByEmail(email)
        .then(function (user) {
            if (!user.verified) {
                return reject({ code: 'USER_VERIFICATION_PENDING' });
            } else {
                var OTPGenObject = new OTPClass(6);
                user.verfOtp = {};
                user.verfOtp.OTP = OTPGenObject.generateOTP();
                user.verfOtp.time = new Date();
                saveUser(user)
                .then(function (user) {
                    sendForgotOTP(user);
                    return resolve({ message: 'An eamil is sent with the verification code to the registered email address.' });
                }, function (error) {
                    return reject(error);
                });
            }
        }, function (error) {
            return reject(error);
        });
    });
}

function resetAfterForgot(email, otp, newPassword) {
    return new Promise(function (resolve, reject) {
        findByEmail(email)
            .then(function (user) {
                if (user.verfOtp.OTP === Number(otp)) {
                    var currentDate = new Date();
                    var otpAgeInMinutes = ((currentDate - user.verfOtp.time) / 1000) / 60;
                    if (otpAgeInMinutes > 5) {
                        return reject({ code: 'EXPIRED_OTP' });
                    } else {
                        user.password = newPassword;
                        saveUser(user)
                        .then(function (user) {
                            return resolve({ message: 'ok' });
                        }, function (error) {
                            return reject(error);
                        });
                    }
                } else {
                    return reject({ code: 'OTP_MISMATCH' });
                }
            }, function (error) {
                return reject(error);
            });
    });
}

function resetMyPassword(user, newPassword) {
    return new Promise(function (resolve, reject) {
        if (newPassword && newPassword !== null) {
            user.password = newPassword;
            saveUser(user)
            .then(function (user) {
                return resolve({ message: 'ok' });
            }, function (error) {
                return reject(error);
            });
        } else {
            return reject({ code: 'PASSWORD_MISSING' });
        }
    });
}

function updateProfilePicture(user, profileImageURL, mimeType) {
    return new Promise(function (resolve, reject) {
        User.update({ _id: user._id }, { $set: { profileImageURL: { url: profileImageURL, mimeType: mimeType } } }, function (error, status) {
            if (error) {
                return reject(error);
            } else {
                if (status.nModified > 0) {
                    return resolve({ message: 'Profile picture updated successfully' });
                } else {
                    return reject({ code: 'PROFILE_PICTURE_UPDATE_ERROR' });
                }
            }
        });
    });
}

/*
 *
 * ##################### END OF EXPORT FUNCTIONS #################################
 *
 * */


function generateJwtToken (user) {
    var secret = config.app.jwt_secret;
    var payload = { user: user };
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
    delete user.verfOtp;
    return user;
}

function getChannelClass(channel) {
    var channelObject;
    var basePath = './modules/core/server/helpers/social_login/';
    switch (channel) {
    case 'facebook':
        channelObject = require(path.resolve(basePath + 'facebook'));
        break;
    case 'google':
        channelObject = require(path.resolve(basePath + 'google'));
        break;
    case 'linkedin':
        channelObject = require(path.resolve(basePath + 'linkedin'));
        break;
    }
    return channelObject;
}

function sendOTP(user) {
    return new Promise(function (resolve, reject) {
        // Read templete file
        var htmlString = '';
        fs.readFile('./modules/users/server/templates/signup-verify-with-otp-email.server.view.html', 'UTF8', function (err, data) {
            if (err) {
                htmlString = 'Please use this OTP to vefify your email address ' + user.verfOtp.OTP;
            } else {
                htmlString = data;
            }
            var template = Handlebars.compile(htmlString);
            var emailHtml = template({
                user: user
            });

            var mailOptions = {
                to: user.email,
                from: config.mailer.from,
                subject: 'Welcome to Carryr',
                html: emailHtml
            };

            smtpTransport.sendMail(mailOptions, function (err) {
                return resolve();
            });
        });
    });
}

function sendForgotOTP(user) {
    return new Promise(function (resolve, reject) {
        // Read templete file
        var htmlString = '';
        fs.readFile('./modules/users/server/templates/reset-password-email.server.view.html', 'UTF8', function (err, data) {
            if (err) {
                htmlString = 'Please use this Verification code to reset your password ' + user.verfOtp.OTP;
            } else {
                htmlString = data;
            }
            var template = Handlebars.compile(htmlString);
            var emailHtml = template({
                user: user
            });

            var mailOptions = {
                to: user.email,
                from: config.mailer.from,
                subject: 'Forgot password',
                html: emailHtml
            };

            smtpTransport.sendMail(mailOptions, function (err) {
                return resolve();
            });
        });
    });
}


module.exports = {
    signUp: signUp,
    resendSignUpOTP: resendSignUpOTP,
    validateEmail: validateEmail,
    jwtSignIn: jwtSignIn,
    socialSignUpLogin: socialSignUpLogin,
    forgotPassword: forgotPassword,
    resetAfterForgot: resetAfterForgot,
    resetMyPassword: resetMyPassword,
    updateProfilePicture: updateProfilePicture
};
