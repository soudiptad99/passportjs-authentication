var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy  = require('passport-facebook').Strategy;
var TwitterStrategy  = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var User = require('../models/user');
var auth = require('./auth');

module.exports = function(passport) {

    // Configure Passport authenticated session persistence.
    //
    // In order to restore authentication state across HTTP requests, Passport needs
    // to serialize users into and deserialize users out of the session.  The
    // typical implementation of this is as simple as supplying the user ID when
    // serializing, and querying the user record by ID from the database when
    // deserializing.
	passport.serializeUser(function(user, done) {
	    done(null, user.id);
	});
	passport.deserializeUser(function(id, done) {
	    User.findById(id, function(err, user) {
	        done(err, user);
	    });
	});


    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-registration', new LocalStrategy({
            // By default, local strategy uses username and password
            // Both fields define the name of the properties in the POST body that are sent to the server.
            usernameField: 'username',  // Optional, defaults to 'username'
            passwordField: 'password',  // Optional, defaults to 'password'
            passReqToCallback: true     // allows us to pass back the entire request to the callback
            // session: false   // if session support is not necessary
        },
        function(req, username, password, done) {

            if (req.body.password !== req.body.confirmPassword) {
                return done(null, false, req.flash('failMessage', 'Your passwords does not match.'));
            }

            // asynchronous
            // User.findOne wont fire unless data is sent back
            process.nextTick(function() {

                // find a user whose username or email is the same as the forms username or email
                User.find( { $or:[ {'local.username': username}, {'local.email': req.body.email} ]}, function(err, users) {
                    if (err) {
                        return done(err);
                    }

                    // check to see if theres already a user with that username
                    if (users.length > 0) {
                        if (users[0].local.username === req.body.username) {
                            return done(null, false, req.flash('failMessage', 'That username is already taken.'));
                        } else if (users[0].local.email === req.body.email) {
                            return done(null, false, req.flash('failMessage', 'A user with that email already exists.'));
                        }
                    } else {
                        // if there is no user with that username, create the user
                        var newUser = new User();

                        // set the user's local credentials
                        newUser.local.firstName = req.body.fname;
                        newUser.local.lastName = req.body.lname;
                        newUser.local.email = req.body.email;
                        newUser.local.username = username;
                        newUser.local.password = newUser.generateHash(password);

                        // save the user
                        newUser.save(function(err) {
                            if (err) {
                                throw err;
                            }
                            return done(null, newUser);
                        });
                    }
                });

            });

        }

    ));


    passport.use('local-login', new LocalStrategy({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, username, password, done) {

            // find a user whose email is the same as the forms email
            // we are checking to see if the user trying to login already exists
            User.findOne({ 'local.username': username }, function(err, user) {

                // if there are any errors, return the error before anything else
                if (err) {
                    return done(err);
                }

                // if no user is found, return the message
                if (!user) {
                    return done(null, false, req.flash('failMessage', 'No user with that username found.'));  // req.flash is the way to set flashdata using connect-flash
                }

                // if the user is found but the password is wrong
                if (!user.validPassword(password)) {
                    return done(null, false, req.flash('failMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata
                }

                // all is well, return successful user
                return done(null, user);
            });

        }
    ));


    passport.use(new FacebookStrategy({

            // import crednetials from auth.js
            clientID: auth.facebook.clientID,
            clientSecret: auth.facebook.clientSecret,
            callbackURL: auth.facebook.callbackURL

        }, function(token, refreshToken, profile, done) {   // fb will send back the 'token' and 'profile'

            // process.nextTick() for asynchronous
            process.nextTick(function() {
                User.findOne({'facebook.id': profile.id}, function(err, user) {
                    if (err) {
                        return done(err);
                    } 
                        console.log(profile)
                    // if the user is found, then log them in
                    if (user) {
                        return done(null, user);    // user found, return that user
                    } else {

                        var newUser = User();
                        newUser.facebook.id = profile.id;
                        newUser.facebook.token = token;     // the token that facebook provides to the user
                        newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName; // http://passportjs.org/docs/profile
                        // newUser.facebook.email = profile.emails.value ? profile.emails.value : 'undefined'; // facebook can return multiple emails so we'll take the first
                    }

                    // save user to the database
                    newUser.save(function(err) {
                        if (err) {
                            throw err;
                        }
                        // if successful, return the new user
                        return done(null, newUser);                      
                    });
                });
            });

        }
    ));


    passport.use(new TwitterStrategy({

            // import crednetials from auth.js
            consumerKey: auth.twitter.consumerKey,
            consumerSecret: auth.twitter.consumerSecret,
            callbackURL: auth.twitter.callbackURL

        }, function(token, tokenSecret, profile, done) {   // fb will send back the 'token' and 'profile'

            // process.nextTick() for asynchronous
            process.nextTick(function() {
                User.findOne({'twitter.id': profile.id}, function(err, user) {
                    if (err) {
                        return done(err);
                    } 
                        console.log(profile)
                    // if the user is found, then log them in
                    if (user) {
                        return done(null, user);    // user found, return that user
                    } else {

                        var newUser = User();
                        newUser.twitter.id = profile.id;
                        newUser.twitter.token = token;
                        newUser.twitter.username = profile.username;
                        newUser.twitter.displayName = profile.displayName;
                    }

                    // save user to the database
                    newUser.save(function(err) {
                        if (err) {
                            throw err;
                        }
                        // if successful, return the new user
                        return done(null, newUser);                      
                    });
                });
            });

        }
    ));



    passport.use(new GoogleStrategy({

            // import crednetials from auth.js
            clientID: auth.google.clientID,
            clientSecret: auth.google.clientSecret,
            callbackURL: auth.google.callbackURL

        }, function(token, refreshToken, profile, done) {   // fb will send back the 'token' and 'profile'

            // process.nextTick() for asynchronous
            process.nextTick(function() {
                User.findOne({'google.id': profile.id}, function(err, user) {
                    if (err) {
                        return done(err);
                    } 
                        console.log(profile)
                    // if the user is found, then log them in
                    if (user) {
                        return done(null, user);    // user found, return that user
                    } else {

                        var newUser = User();
                        newUser.google.id = profile.id;
                        newUser.google.token = token;
                        newUser.google.email = profile.emails[0].value;
                        newUser.google.name = profile.displayName;
                    }

                    // save user to the database
                    newUser.save(function(err) {
                        if (err) {
                            throw err;
                        }
                        // if successful, return the new user
                        return done(null, newUser);                      
                    });
                });
            });

        }
    ));


};