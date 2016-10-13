var express = require('express');
var passport = require('passport');
var nodemailer = require('nodemailer');
var User = require('../models/user');
var middleware = require('../middleware/custom');
var encryption = require('../data/encryption');
var email = require('../email/nodemailer');

var router = express.Router();


router.get('/', function(req, res) {
	res.render('home');
});

router.get('/register', middleware.redirectIfLogged, function(req, res) {
	res.render('register', {
		title: 'Register',
		failMessage: req.flash('registerMessage')
	});
});

router.post('/register', passport.authenticate('local-registration', {
    successRedirect : '/dashboard',
    failureRedirect : '/register', 	
    failureFlash : true 
}));

router.get('/login', middleware.redirectIfLogged, function(req, res) {
	res.render('login', {
		title: 'Login',
		failMessage: req.flash('loginMessage'),
		successMessage: req.flash('passwordChanged')
	});
});

router.post('/login', passport.authenticate('local-login', {
    successRedirect : '/dashboard', 
    failureRedirect : '/login', 
    failureFlash : true 
}));

router.get('/dashboard', middleware.continueIfLogged, function(req, res) {
	res.render('dashboard', {
		title: 'Dashboard',
		user: req.user
	});
});

router.get('/account', middleware.continueIfLogged, function(req, res) {
	res.render('account', {
		title: 'Acount',
		user: req.user
	});
});

router.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

router.get('/users', middleware.continueIfLogged, function(req, res) {
	User.find({}, function(err, users) {
		res.render('users', {
			title: 'Users',
			users: users
		});
	});
});

router.get('/forgot', function(req, res) {
	res.render('forgot', {
		title: 'Forgot Password',
		user: req.user,
		failMessage: req.flash('resetMessage')
	});
});

router.post('/forgot', function(req, res) {
	User.findOne({'local.email': req.body.email}, function(err, user) {
		if (!user) {
			req.flash('resetMessage', 'No user with that email found.');
			return res.redirect('/forgot');
		} else {
			var token = encryption.generateString(30);
			user.local.resetPasswordToken = token;		// generate a 512 bits cipher
			user.local.resetPasswordExpires = Date.now() + 3600000; 	// expires in 1 hour
			user.save(function(err) {
				if (err) {
					req.flash('resetMessage', err.message);
				} else {
					email.forgotPassword(req, user, token, function() {
						req.flash('resetMessage', 'An e-mail has been sent to ' + user.local.email + ' with further instructions.');
						res.redirect('/forgot');				
					});					
				}
			});
		}
	});
});

router.get('/reset/:token', function(req, res) {
    User.findOne({ 'local.resetPasswordToken': req.params.token, 'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('resetMessage', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.render('reset', { 
        	user: req.user,
        	failMessage: req.flash('passwordChanged')
        });
    });
});

router.post('/reset/:token', function(req, res) {
	if (req.body.password !== req.body.confirmPassword) {
		req.flash('passwordChanged', 'Your password does not match.');
		return res.redirect('/reset/' + req.params.token);
	}
    User.findOne({ 'local.resetPasswordToken': req.params.token, 'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('resetMessage', 'Password reset token is invalid or has expired.');
            return res.redirect('back');
        } else {
            user.local.password = user.generateHash(req.body.password);
            user.local.resetPasswordToken = undefined;
            user.local.resetPasswordExpires = undefined;
            user.save(function(err) {
                if (err) {
                    req.flash('resetMessage', err.message);
                } else {
                    email.resetPassword(req, user, function() {
                        req.flash('passwordChanged', 'Success! Your password has been changed.');
                        res.redirect('/login');
                    });
                }
            });
        }
    });
});


module.exports = router;