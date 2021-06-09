import User from '../../models/User.js';
import bcrypt from 'bcrypt';
import * as auth from '../../middlewares/auth.js';
import sendEmail from '../../utils/sendEmail.js';
import crypto from 'crypto';

export const register = async (req, res) => {
	try {
		const { firstName, lastName, email, password, confirmPassword } = req.body;

		let username = req.body.username;

		if (!username) {
			[username] = email.split('@');
		} else if (!username.trim('').length) {
			[username] = email.split('@');
		}

		const userByEmail = { email: email };

		const userByUsername = await User.findOne({ username });

		if (userByUsername) {
			return res.send({
				message: `${username} is already taken. Please use another.`,
			});
		}

		User.findOne(userByEmail)
			.then(user => {
				if (user) {
					return res.status(400).send({
						message: `${user.email} is already registered.`,
					});
				}

				if (password !== confirmPassword) {
					return res.status(400).send({
						message: `Passwords do not match.`,
					});
				}

				const hashedPw = bcrypt.hashSync(password, 10);

				const newUser = new User({
					firstName: firstName,
					lastName: lastName,
					username: username,
					email: email,
					password: hashedPw,
					role: 'admin',
				});

				const _newUser = {
					name: newUser.fullName,
					username: username,
					email: email,
				};

				newUser
					.save()
					.then(user => {
						if (user) {
							return res.send({
								message: `Hi ${firstName}, you've successfully created an account.`,
								user: _newUser,
							});
						}
					})
					.catch(err => {
						console.log(err);
						return res.send(err.message);
					});
			})
			.catch(err => {
				console.log(err);
				res.send(err.message);
			});
	} catch (err) {
		console.log(err);
		res.send(err.message);
	}
};

export const login = async (req, res) => {
	try {
		let userByEmail = { email: req.body.email };

		User.findOne(userByEmail)
			.then(user => {
				if (!user) {
					return res.status(400).send({
						message: `${userByEmail.email} is not yet registered.`,
					});
				}

				if(user.role !== 'admin') {
					return res.status(400).send({
						message: `Non-admin users are not allowed to use this log in.`,
					});
				}

				const isPasswordCorrect = bcrypt.compareSync(
					req.body.password,
					user.password
				);

				if (isPasswordCorrect) {
					const token = auth.createAccessToken(user);

					return res.send({
						token: token,
						message: `${user.fullName} was logged in successfully.`,
					});
				} else {
					return res.status(400).send({ message: 'Invalid password' });
				}
			})
			.catch(err => {
				console.log(err);
				res.send(err.message);
			});
	} catch (err) {
		console.log(err);
		res.send(err.message);
	}
};

export const forgotPassword = async (req, res) => {
	const { email } = req.body;

	try {
		const user = await User.findOne({ email });

		if (!user) {
			return res.status(400).send({
				message: `${email} is not yet registered.`,
			});
		}

		const resetToken = user.getResetPasswordToken();

		await user.save();

		const message = `
		<h1>Hello ${user.firstName},</h1>
		<p>Please use the below reset token to reset your password.</p>
		<p> ${resetToken} </p>
	`;

		try {
			sendEmail({
				to: user.email,
				subject: 'Password Reset Request',
				text: message,
			});

			return res.send({
				success: true,
				message: `Hello ${user.firstName}, please check your email to reset your password.`,
			});
		} catch (err) {
			user.resetPasswordToken = undefined;
			user.resetPasswordExpire = undefined;

			await user.save();

			return res.status(500).send({
				message: 'Email could not be sent.',
			});
		}
	} catch (err) {
		console.log(err);
	}
};

export const resetPassword = async (req, res) => {
	const resetPasswordToken = crypto
		.createHash('sha256')
		.update(req.params.resetToken)
		.digest('hex');

	try {
		const user = await User.findOne({
			resetPasswordToken,
			resetPasswordExpire: { $gt: Date.now() },
		});

		if (!user) {
			return res.status(400).send({
				message: 'Invalid reset token.',
			});
		}

		const hashedPw = bcrypt.hashSync(req.body.password, 10);

		user.password = hashedPw;
		user.resetPasswordToken = undefined;
		user.resetPasswordExpire = undefined;

		await user.save();
		return res.send({
			success: true,
			message: `Hello ${user.firstName}, you've successfully reset your password.`,
		});
	} catch (err) {
		console.log(err);
	}
};
