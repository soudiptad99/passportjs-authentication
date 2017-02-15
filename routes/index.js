var express = require('express');
var passport = require('passport');
var nodemailer = require('nodemailer');
var crypto = require('crypto');
var User = require('../models/user');
var middleware = require('../middleware/custom');
var email = require('../email/nodemailer');

var router = express.Router();

// GET /
router.get('/', function(req, res) {
	res.render('home');
});

// GET /register
router.get('/register', middleware.redirectIfLogged, function(req, res) {
	res.render('register', {
		title: 'Register',
		failMessage: req.flash('failMessage')
	});
});

// POST /register
router.post('/register', passport.authenticate('local-registration', {
    successRedirect : '/dashboard',
    failureRedirect : '/register', 	
    failureFlash : true 
}));

// GET /login
router.get('/login', middleware.redirectIfLogged, function(req, res) {
	res.render('login', {
		title: 'Login',
		failMessage: req.flash('failMessage'),
		successMessage: req.flash('successMessage')
	});
});

// POST /login
router.post('/login', passport.authenticate('local-login', {
    successRedirect : '/dashboard', 
    failureRedirect : '/login', 
    failureFlash : true 
}));

// GET /dashboard
router.get('/dashboard', middleware.continueIfLogged, function(req, res) {
	res.render('dashboard', {
		title: 'Dashboard'
	});
});

// GET /account
router.get('/account', middleware.continueIfLogged, function(req, res) {
	res.render('account', {
		title: 'Acount'
	});
});

// GET /logout
router.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

// GET /users
router.get('/users', middleware.continueIfLogged, function(req, res) {
	User.find({}, function(err, users) {
		res.render('users', {
			title: 'Users',
			users: users
		});
	});
});

// GET /forgot
router.get('/forgot', middleware.redirectIfLogged, function(req, res) {
	res.render('forgot', {
		title: 'Forgot Password',
		successMessage: req.flash('successMessage'),
		failMessage: req.flash('failMessage')
	});
});

// POST /forgot
router.post('/forgot', function(req, res) {
	User.findOne({'local.email': req.body.email}, function(err, user) {
		if (!user) {
			req.flash('failMessage', 'No user with that email found.');
			return res.redirect('/forgot');
		} else {
			var token = crypto.createHash('md5').digest('hex');	// generate a md5 hash that is 128 bits long
			user.resetPasswordToken = token;
			user.resetPasswordExpires = Date.now() + 3600000; 	// expires in 1 hour
			user.save(function(err) {
				if (err) {
					req.flash('failMessage', err.message);
				} else {
					email.forgotPassword(req, user, token, function() {
						req.flash('successMessage', 'An e-mail has been sent to ' + user.local.email + ' with further instructions.');
						res.redirect('/forgot');				
					});					
				}
			});
		}
	});
});

// GET /reset/:token
router.get('/reset/:token', function(req, res) {
    User.findOne({ 'resetPasswordToken': req.params.token, 'resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('failMessage', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.render('reset', {
        	failMessage: req.flash('successMessage')
        });
    });
});

// POST /reset/:token
router.post('/reset/:token', function(req, res) {
	if (req.body.password !== req.body.confirmPassword) {
		req.flash('failMessage', 'Your password does not match.');
		return res.redirect('/reset/' + req.params.token);
	}
    User.findOne({ 'resetPasswordToken': req.params.token, 'resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('failMessage', 'Password reset token is invalid or has expired.');
            return res.redirect('back');
        } else {
            user.local.password = user.generateHash(req.body.password);
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            user.save(function(err) {
                if (err) {
                    req.flash('failMessage', err.message);
                } else {
                    email.resetPassword(req, user, function() {
                        req.flash('successMessage', 'Success! Your password has been changed.');
                        res.redirect('/login');
                    });
                }
            });
        }
    });
});



/////////// Social media account authentications

// GET /auth/facebook
router.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

// POST /auth/facebook/callback
router.get('/auth/facebook/callback', passport.authenticate('facebook', {
    successRedirect : '/dashboard',
    failureRedirect : '/login'
}));

// GET /auth/twitter
router.get('/auth/twitter', passport.authenticate('twitter'));

// POST /auth/twitter/callback
router.get('/auth/twitter/callback', passport.authenticate('twitter', {
    successRedirect : '/dashboard', 
    failureRedirect : '/login', 
}));

// GET /auth/google
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// POST /auth/google/callback
router.get('/auth/google/callback', passport.authenticate('google', {
    successRedirect : '/dashboard',
    failureRedirect : '/login'
}));


/////////// Linking accounts

// GET /connect/local
router.get('/connect/local', function(req, res) {
    res.render('connect-local', { 
    	successMessage: req.flash('successMessage'),
    	failMessage: req.flash('failMessage')
    });
});

// POST /connect/local
router.post('/connect/local', passport.authenticate('local-registration', {
    successRedirect : '/dashboard', 	// redirect to the secure profile section
    failureRedirect : '/connect/local', // redirect back to the /connect/local page if there is an error
    failureFlash : true 				// allow flash messages
}));

// GET /connect/facebook
router.get('/connect/facebook', passport.authorize('facebook', { scope : ['email'] }));

// POST /connect/facebook - handle the callback after facebook has authorized the user
router.get('/connect/facebook/callback', passport.authorize('facebook', {
    successRedirect : '/dashboard',
    failureRedirect : '/login'
}));

// GET /connect/twitter
router.get('/connect/twitter', passport.authorize('twitter', { scope : 'email' }));

// POST /connect/twitter - handle the callback after twitter has authorized the user
router.get('/connect/twitter/callback', passport.authorize('twitter', {
    successRedirect : '/dashboard',
    failureRedirect : '/login'
}));

// GET /connect/google
router.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));

// POST /connect/google - the callback after google has authorized the user
router.get('/connect/google/callback', passport.authorize('google', {
    successRedirect : '/dashboard',
    failureRedirect : '/login'
}));


/////////// Unlinking accounts
// user account will stay active in case they want to reconnect in the future

// GET /unlink/local
router.get('/unlink/local', function(req, res, next) {
	if (!req.user) {
		return next();
	}
    var user = req.user;
    user.local.username = undefined;
    user.local.password = undefined;
    user.save(function(err) {
    	if (err) return next(err);
        res.redirect('/dashboard');
    });
});

// GET /unlink/facebook
router.get('/unlink/facebook', function(req, res, next) {
	if (!req.user) {
		return next();
	}
    var user = req.user;
    user.facebook.token = undefined;
    user.save(function(err) {
    	if (err) return next(err);
        res.redirect('/dashboard');
    });
});

// GET /unlink/twitter
router.get('/unlink/twitter', function(req, res, next) {
	if (!req.user) {
		return next();
	}
    var user = req.user;
    user.twitter.token = undefined;
    user.save(function(err) {
    	if (err) return next(err);
        res.redirect('/dashboard');
    });
});

// GET /unlink/google
router.get('/unlink/google', function(req, res, next) {
	if (!req.user) {
		return next();
	}
    var user = req.user;
    user.google.token = undefined;
    user.save(function(err) {
    	if (err) return next(err);
        res.redirect('/dashboard');
    });
});


module.exports = router;