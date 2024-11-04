import { Request } from 'express';
import createAppLog from './utils/createLog';
import redisClient from './utils/redisClient';

export const getUserDataFromSession = async (email: string) => {
  try {
    const tempUser = await redisClient.get(`${email}_tempUser`);
    if (!tempUser) {
      createAppLog(JSON.stringify({ Error: 'User data not found in Redis' }));
      return null;
    }
    return JSON.parse(tempUser);
  } catch (err: any) {
    createAppLog(
      JSON.stringify({ Error: `Failed to retrieve user data: ${err.message}` })
    );
    return null;
  }
};

export const deleteUserDataFromSession = async (req: Request) => {
  // Remove tempUser data from the session
  if (req.session) {
    delete req.session.tempUser;
  }
};

export const deleteOtpDataFromSession = async (req: Request) => {
  // Remove tempUser data from the session
  if (req.session) {
    delete req.session.otpData;
  }
};
