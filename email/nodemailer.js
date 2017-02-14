var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport('SMTP', {
    service: 'SendGrid',
    secure: true,	// use SSL
    auth: {
        user: 'YOUR ACCOUNT HERE',
        pass: 'YOUR PASSWORD HERE'
    }
});
// var mailOptions = {
//     from: '"Fred Foo 👥" <foo@blurdybloop.com>', // sender address
//     to: 'bar@blurdybloop.com, baz@blurdybloop.com', // list of receivers
//     subject: 'Hello ✔', // Subject line
//     text: 'Hello world 🐴', // plaintext body
//     html: '<b>Hello world 🐴</b>' // html body
// };


module.exports.forgotPassword = function(req, user, token, callback) {

    var mailOptions = {
        from: '"Administrator 👥" <administrator@nodejs.com>',
        to: user.local.email,
        subject: 'Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
    };

    transporter.sendMail(mailOptions, function(err, info) {
        if (err) {
            return console.log(err);
        } else {
            callback();
        }
    });

};

module.exports.resetPassword = function(req, user, callback) {

    var mailOptions = {
        from: '"Administrator 👥" <administrator@nodejs.com>',
        to: user.local.email,
        subject: 'Your password has been changed',
        text: 'Hello ' + user.local.firstName + ',' + '\n\n' +
            'This is a confirmation that the password for your account ' + user.local.email + ' has just been changed.\n'
    };

    transporter.sendMail(mailOptions, function(err, info) {
        if (err) {
            return console.log(err);
        } else {
            callback();
        }
    });

}
