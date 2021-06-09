import express from 'express';
const router = express.Router();
import * as auth from '../../controllers/admin/auth.js';
import * as v from '../../middlewares/validators.js';
import * as a from '../../middlewares/auth.js';

router.post(
	'/register',
	v.validateRegisterRequest,
	v.isRequestValidated,
	auth.register
);

router.post('/login', v.validateLoginRequest, v.isRequestValidated, auth.login);

router.post('/forgotpassword', auth.forgotPassword);
router.put('/resetpassword/:resetToken', auth.resetPassword);

router.post('/profile', a.verify, (req, res) => {
	res.send({ user: 'profile' });
});

export default router;
