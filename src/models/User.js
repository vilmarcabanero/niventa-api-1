import mongoose from 'mongoose';
import crypto from 'crypto';

const UserSchema = new mongoose.Schema(
	{
		firstName: {
			type: String,
			required: true,
			trim: true,
			min: 3,
			max: 20,
		},
		lastName: {
			type: String,
			required: true,
			trim: true,
			min: 3,
			max: 20,
		},
		username: {
			type: String,
			trim: true,
			unique: true,
			index: true,
		},
		email: {
			type: String,
			required: true,
			trim: true,
			unique: true,
			lowercase: true,
		},
		password: {
			type: String,
			required: true,
		},
		resetPasswordToken: String,
		resetPasswordExpire: Date,
		role: {
			type: String,
			enum: ['user', 'admin', 'super-admin'],
			default: 'user',
		},
		contactNumber: {
			type: String,
		},
		pofilePicture: {
			type: String,
		},
	},
	{
		timestamps: true,
	}
);

UserSchema.virtual('fullName').get(function () {
	return `${this.firstName} ${this.lastName}`;
});

UserSchema.methods.getResetPasswordToken = function () {
	const resetToken = crypto.randomBytes(20).toString('hex');

	this.resetPasswordToken = crypto
		.createHash('sha256')
		.update(resetToken)
		.digest('hex');

	this.resetPasswordExpire = Date.now() + 10 * (60 * 1000);

	return resetToken;
};

export default mongoose.model('User', UserSchema);
