// https://scotch.io/tutorials/easy-node-authentication-setup-and-local
// http://sahatyalkabov.com/how-to-implement-password-reset-in-nodejs/

var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var path = require('path');
var handlebars = require('express-handlebars');
var mongoose = require('mongoose');
var passport = require('passport');
var session = require('express-session');
var flash = require('connect-flash');
var mongoStore = require('connect-mongo')(session);
var middleware = require('./middleware/custom');
var routes = require('./routes/index');

var app = express();

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://127.0.0.1:27017/passport', function(err) {
	if (err) {
		console.error(err.message);
	} else {
		console.log('Successfully connected to MongoDB');
	}
});

app.set('port', process.env.PORT || 3000);
app.set('view engine', 'handlebars');
app.engine('handlebars', handlebars({defaultLayout: 'main'}));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, '/bower_components')));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(session({
	secret: '9Jy2oScW04',
	resave: false,
	saveUninitialized: false,
	// use MongoDB as session store
	store: new mongoStore({mongooseConnection: mongoose.connection})
}));

// initialize Passport
app.use(passport.initialize());

// restore authentication state, if any, from the session
app.use(passport.session());

// use connect-flash for flash messages stored in session
app.use(flash());

// Determine if the user is logged in or not
app.use(middleware.isLoggedIn);

// passport strategies
require('./passport/strategies')(passport);

// main routes
app.use('/', routes);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// development error handler - will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
        	title: err.message,
            message: err.message,
            error: err
        });
    });
}

// production error handler - no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


app.listen(app.get('port'), function() {
	console.log('Server is running %s mode and is listening on port %s', app.get('env'), app.get('port'));
});