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
			user.local.resetPasswordToken = token;
			user.local.resetPasswordExpires = Date.now() + 3600000; 	// expires in 1 hour
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
    User.findOne({ 'local.resetPasswordToken': req.params.token, 'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
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
    User.findOne({ 'local.resetPasswordToken': req.params.token, 'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('failMessage', 'Password reset token is invalid or has expired.');
            return res.redirect('back');
        } else {
            user.local.password = user.generateHash(req.body.password);
            user.local.resetPasswordToken = undefined;
            user.local.resetPasswordExpires = undefined;
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


module.exports = router;