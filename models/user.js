var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

var userSchema = new mongoose.Schema({
	local: {
		username: {
			type: String,
			trim: true
			// unique: true,
			// required: true,
		},
		firstName: {
			type: String,
			trim: true
		},
		lastName: {
			type: String,
			trim: true
		},
		email: {
			type: String,
			trim: true
			// unique: true,
			// required: true,
		},
		password: {
			type: String,
			// unique: true,
			// required: true,
		},
		privilege: {
			type: String,
			trim: true
		},
		resetPasswordToken: String,
  		resetPasswordExpires: Date
	}

});

userSchema.methods.generateHash = function(password) {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', userSchema);