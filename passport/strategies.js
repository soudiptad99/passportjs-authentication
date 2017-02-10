var LocalStrategy = require('passport-local').Strategy;
var User = require('../models/user');

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

                // find a user whose username is the same as the forms username
                // we are checking to see if the user trying to login already exists
                // User.findOne({'local.username': username}, function(err, user) {
                //     // if there are any errors, return the error
                //     if (err) {
                //         return done(err);
                //     }

                //     // check to see if theres already a user with that username
                //     if (user) {
                //         return done(null, false, req.flash('registerMessage', 'That username is already taken.'));
                //     } else {

                //         // if there is no user with that username, create the user
                //         var newUser = new User();

                //         // set the user's local credentials
                //         newUser.local.firstName = req.body.fname;
                //         newUser.local.lastName = req.body.lname;
                //         newUser.local.email = req.body.email;
                //         newUser.local.username = username;
                //         newUser.local.password = newUser.generateHash(password);

                //         // save the user
                //         newUser.save(function(err) {
                //             if (err) {
                //                 throw err;
                //             }
                //             return done(null, newUser);
                //         });
                //     }

                // });

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



};