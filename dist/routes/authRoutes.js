"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRouter = void 0;
const express_1 = require("express");
const auth_1 = require("../controllers/auth");
const profilePhoto_1 = require("../controllers/profilePhoto");
const eventEmitter_1 = __importDefault(require("../utils/eventEmitter"));
const registration_1 = require("../controllers/registration");
const forgotPassword_1 = require("../controllers/forgotPassword");
const userValidtor_1 = require("../validators/userValidtor");
// Set up the event listener to use the function
eventEmitter_1.default.on('userVerified', registration_1.completeRegistration);
const authRouter = (0, express_1.Router)();
exports.authRouter = authRouter;
authRouter.post('/signup', userValidtor_1.validateUserSignup, auth_1.SignUp);
authRouter.post('/verify-otp', auth_1.verifyOTP);
//Use multer to handle multipart/form-data requests.
authRouter.post('/login', profilePhoto_1.upload.none(), auth_1.Login);
authRouter.post('/logout', auth_1.Logout);
authRouter.post('/forgot-password', forgotPassword_1.ForgotPassword);
authRouter.put('/reset-password', forgotPassword_1.ResetPassword);
