import { Router } from 'express';
import { Login, SignUp, verifyOTP, Logout } from '../controllers/auth';
import { upload } from '../controllers/profilePhoto';
import eventEmitter from '../utils/eventEmitter';
import { completeRegistration } from '../controllers/registration';
import { ForgotPassword, ResetPassword } from '../controllers/forgotPassword';
import { validateUserSignup } from '../validators/userValidtor';

// Set up the event listener to use the function
eventEmitter.on('userVerified', completeRegistration);

const authRouter = Router();

authRouter.post('/signup', validateUserSignup, SignUp);
authRouter.post('/verify-otp', verifyOTP);

//Use multer to handle multipart/form-data requests.
authRouter.post('/login', upload.none(), Login);

authRouter.post('/logout', Logout);
authRouter.post('/forgot-password', ForgotPassword);
authRouter.put('/reset-password', ResetPassword);

export { authRouter };
