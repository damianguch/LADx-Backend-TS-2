import User, { IUser } from '../models/user';
import { getUserDataFromSession } from '../helper';
import { generateToken } from '../utils/jwt';
import logger from '../logger/logger';
import LogFile from '../models/LogFile';
import currentDate from '../utils/date';
import createAppLog from '../utils/createLog';
import redisClient from '../utils/redisClient';

const completeRegistration = async (email: string) => {
  // Fetch temporary user data from session or Redis
  const tempUser = await getUserDataFromSession(email);

  if (!tempUser) {
    createAppLog(JSON.stringify({ Error: 'User data not found' }));
    return;
  }

  try {
    const newUser = new User(tempUser);
    await User.init();
    const user: IUser = await newUser.save();

    // Log the OTP verification activity
    const otpLog = new LogFile({
      email: tempUser.email,
      ActivityName: 'User Verified OTP',
      AddedOn: currentDate
    });

    await otpLog.save();

    // Log the new user creation activity
    const logEntry = new LogFile({
      fullname: tempUser.fullname,
      email: tempUser.email,
      ActivityName: `New user created with email: ${tempUser.email}`,
      AddedOn: currentDate
    });
    await logEntry.save();

    // Clear tempUser data from Redis
    await redisClient.del(`${email}_tempUser`);
    // Generate a JWT token for the user
    const token = generateToken({ email: newUser.email, id: newUser.id });

    // Info level logging
    logger.info(`User account created. - ${user.email}`, {
      timestamp: new Date().toISOString()
    });

    // Log success
    createAppLog(
      JSON.stringify({ Success: `User account created for ${user.email}` })
    );

    // res
    //   .cookie('token', token, {
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     sameSite: 'none',
    //     maxAge: 60 * 60 * 1000
    //   })
    //   .status(200)
    //   .json({
    //     status: '00',
    //     success: true,
    //     message: 'User account created successfully'
    //   });
  } catch (err: any) {
    createAppLog(JSON.stringify({ Error: err.message }));
    // Error level logging
    logger.error(`Error creating User account: ${err.message}`, {
      timestamp: new Date().toISOString()
    });
    // res.status(500).json({
    //   status: '00',
    //   success: true,
    //   message: `Error creating user: ${err.message}`
    // });
  }
};

export { completeRegistration };
