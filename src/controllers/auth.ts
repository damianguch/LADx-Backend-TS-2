/*************************************************************************
 * Controller: User Authentication Controller
 * Description: Controller contains functions for all user authentictions.
 * Author: Damian Oguche
 * Date: 02-10-2024
 **************************************************************************/

import User, { IUser } from '../models/user';
import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { generateToken } from '../utils/jwt';
import LogFile from '../models/LogFile';
import EmailCode from '../utils/randomNumbers';
import createAppLog from '../utils/createLog';
import encryptPasswordWithBcrypt from '../utils/passwordEncrypt';
import currentDate from '../utils/date';
import { sanitizeSignUpInput } from '../utils/sanitize';
import { Request, Response } from 'express';
import { sendOTPEmail } from '../utils/emailService';
import { loginSchema } from '../schema/user.schema';
import { z } from 'zod';
import logger from '../logger/logger';
import { deleteOtpDataFromSession } from '../helper';
import eventEmitter from '../utils/eventEmitter';
import redisClient from '../utils/redisClient';
import { verifyOTPSchema } from '../schema/otp.schema';

// Custom error response interface
interface ErrorResponse {
  status: string;
  success: boolean;
  message: string;
  errors?: z.ZodError['errors'];
}

// @POST: SignUp Route
export const SignUp = async (req: Request, res: Response): Promise<void> => {
  try {
    // Get request body
    const sanitizedData = sanitizeSignUpInput(req.body);
    let { fullname, email, country, state, phone, password } = sanitizedData;

    // Check if email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(400).json({
        status: 'E00',
        success: false,
        message: 'Email already registered'
      });
      return;
    }

    // Hash password for later use (only after OTP verification)
    const encryptedPassword = await encryptPasswordWithBcrypt(password);

    // Save user info temporarily
    const tempUser = {
      fullname,
      email,
      phone,
      country,
      state,
      password: encryptedPassword
    };

    // Generate OTP and hash it
    const otp: string = await EmailCode(6);
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    console.log(otp);

    // Store OTP and email in the session
    req.session.otpData = { hashedOTP, expiresAt: Date.now() + 60 * 60 * 1000 };
    req.session.email = email; // Store email in session

    // Store temp user In-Memory Store(Redis)
    req.session.tempUser = tempUser;

    req.session.save((err) => {
      if (err) {
        // Info level logging
        logger.error(`Session save error`, {
          timestamp: new Date().toISOString()
        });
      }

      // Info level logging
      else
        logger.info('Session saved successfully', {
          timestamp: new Date().toISOString()
        });
    });

    // Send OTP via email
    const result = await sendOTPEmail({ email, otp });

    logger.info(`${result.message} - ${email}`, {
      timestamp: new Date().toISOString()
    });

    res.status(200).json({
      status: '00',
      success: true,
      message: `${result.message} - ${email}`
    });
  } catch (err: any) {
    createAppLog(JSON.stringify({ Error: err.message }));
    res.status(500).json({
      status: 'E00',
      success: false,
      message: 'Internal Server Error: ' + err.message
    });
  }
};

// @POST: OTP Verification Route
export const verifyOTP = async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate the request body using Zod
    const { otp } = verifyOTPSchema.parse(req.body);
    const email = req.session.email; // Retrieve email from session

    if (!otp || !email) {
      res.status(400).json({ message: 'OTP or email not found' });
      return;
    }

    // Fetch stored OTP from session
    const storedOTPData = req.session.otpData;

    if (!storedOTPData) {
      res.status(400).json({ message: 'OTP not found or expired' });
      return;
    }

    const { hashedOTP, expiresAt } = storedOTPData as {
      hashedOTP: string;
      expiresAt: number;
    };

    // Check if OTP has expired
    if (Date.now() > expiresAt) {
      req.session.destroy((err: any) => {
        if (err) {
          createAppLog(JSON.stringify({ Error: err.message }));
        }
      }); // Clear session data
      res.status(400).json({ message: 'OTP expired' });
      return;
    }

    // Verify OTP (Compare otp from req.body and session)
    const isMatch = await bcrypt.compare(otp, hashedOTP);
    if (!isMatch) {
      res.status(400).json({ message: 'Invalid OTP' });
      return;
    }

    // Notify Registration Service, but handle it after response
    res.status(200).json({
      status: '00',
      success: true,
      message: 'OTP verified successfully'
    });

    // Notify Registration Service

    // Emit 'userVerified' event with the user's email
    eventEmitter.emit('userVerified', email);

    const tempUser = req.session.tempUser;
    // Save tempUser to Redis for access by registration service
    await redisClient.set(`${email}_tempUser`, JSON.stringify(tempUser), {
      EX: 3600
    }); // Expire in 1 hour

    // Clear OTP data from session
    await deleteOtpDataFromSession(req);
  } catch (err: any) {
    if (err instanceof z.ZodError) {
      res
        .status(400)
        .json({ message: 'Invalid request body', errors: err.issues });
      return;
    }

    createAppLog(JSON.stringify({ Error: err.message }));
    if (!res.headersSent) {
      res.status(500).json({
        status: 'E00',
        success: false,
        message: `Failed to notify registration service: ${err.message}`
      });
    }
  }
};

// @POST: User Login
export const Login = async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate request body using Zod
    const validationResult = loginSchema.safeParse(req.body);

    // If validation fails, return detailed error response
    if (!validationResult.success) {
      const errorResponse: ErrorResponse = {
        status: 'E00',
        success: false,
        message: 'Validation failed',
        errors: validationResult.error.errors
      };

      await createAppLog(
        `Login validation error: ${JSON.stringify(errorResponse)}`
      );
      res.status(400).json(errorResponse);
      return;
    }

    const { email, password } = validationResult.data;

    // Log login attempt
    await createAppLog(`Login attempt for email: ${email}`);

    // Info level logging
    logger.info(`Login attempt for email: ${email}`, {
      timestamp: new Date().toISOString()
    });

    // Find user by email with select to explicitly choose fields
    const user: IUser = await User.findOne({ email }).select('+password');

    // Check if user exists
    if (!user) {
      await createAppLog(`Login failed: Email not registered - ${email}`);
      // Errorlevel logging
      logger.error(`Login failed: Email not registered - ${email}`, {
        timestamp: new Date().toISOString()
      });
      res.status(401).json({
        status: 'E00',
        success: false,
        message: 'Invalid credentials'
      });
      return;
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      await createAppLog(`Login failed: Incorrect password - ${email}`);
      res.status(401).json({
        status: 'E00',
        success: false,
        message: 'Wrong password.'
      });
      return;
    }

    // Generate JWT token with the user payload
    const token = generateToken({
      email: user.email,
      id: user.id
    });

    // Log the login activity
    await createAppLog(`User logged in successfully: ${email}`);
    const logEntry = new LogFile({
      email: user.email,
      ActivityName: 'User Login',
      AddedOn: currentDate
    });

    await logEntry.save();

    // Set secure, HTTP-only cookie
    res
      .cookie('token', token, {
        httpOnly: true, // Prevent JavaScript access
        secure: process.env.NODE_ENV === 'production' ? true : false, // Only send cookie over HTTPS in production
        sameSite: 'none', // Prevent CSRF attacks if set to Strict
        maxAge: 60 * 60 * 1000 // Cookie expiration time (1 hour)
      })
      .json({
        status: '200',
        success: true,
        message: 'Login successful!',
        email: user.email
      });
  } catch (err: any) {
    await createAppLog(`Login Error:  ${err.message}`);
    res.status(500).json({
      status: 'E00',
      success: false,
      message: `Internal Server error: ${err.message}`
    });
  }
};

// User Logout
export const Logout = async (req: Request, res: Response): Promise<void> => {
  const token = req.cookies.token;

  if (!token) {
    await createAppLog(`No token found!`);
    res.status(401).json({ message: 'No token provided' });
    return;
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY!) as JwtPayload;

  // Log the logout activity
  const logExit = new LogFile({
    email: decoded.email,
    ActivityName: `User ${decoded.email} Logged out of the system`,
    AddedOn: currentDate
  });

  await logExit.save();

  await createAppLog(`User ${decoded.email} logged out!`);
  res
    .clearCookie('token')
    .clearCookie('csrfToken')
    .json({ message: 'User Logged out' });
};
