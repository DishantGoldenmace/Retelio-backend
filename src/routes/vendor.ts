import { Router } from 'express';
import { register, verification, sendOTP, login, forgotPassword, verifyOTPAuthenticate, resendOTP, getProfile, resetPassword, dashboard, changePassword, updateProfile, logout } from '../controllers/vendor'

import { upload } from '../functions/upload'

import { authVendor } from '../middlewares/vendor'

const router = Router();

router.post('/register', register);

router.post('/send-otp/:id/:response', sendOTP);

router.put('/verification/:id/:response?', verification);

router.post('/login', login);

router.post('/forgot-password', forgotPassword);

router.post('/verify-authenticate/:id', verifyOTPAuthenticate);

router.post('/resend-otp/:id', resendOTP);

router.post('/reset-password/:token', resetPassword);

router.get('/dashboard', authVendor, dashboard);

router.get('/get-profile', authVendor, getProfile);

router.put('/change-password', authVendor, changePassword);

router.put('/update-profile', authVendor, upload.single("vendorImage"), updateProfile);

router.post('/logout', logout);

export default router;