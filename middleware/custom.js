function isLoggedIn(req, res, next) {
	res.locals.loggedIn = req.isAuthenticated();
	res.locals.user = req.user;
	next();
};

function continueIfLogged(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	}
	res.redirect('/');
};

function redirectIfLogged(req, res, next) {
	if (req.isAuthenticated()) {
		res.redirect('/dashboard');
	} else {
		next();			
	}
};

module.exports.continueIfLogged = continueIfLogged;
module.exports.redirectIfLogged = redirectIfLogged;
module.exports.isLoggedIn = isLoggedIn;