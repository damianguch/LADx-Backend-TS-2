"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.completeRegistration = void 0;
const user_1 = __importDefault(require("../models/user"));
const helper_1 = require("../helper");
const jwt_1 = require("../utils/jwt");
const logger_1 = __importDefault(require("../logger/logger"));
const LogFile_1 = __importDefault(require("../models/LogFile"));
const date_1 = __importDefault(require("../utils/date"));
const createLog_1 = __importDefault(require("../utils/createLog"));
const redisClient_1 = __importDefault(require("../utils/redisClient"));
const completeRegistration = (email) => __awaiter(void 0, void 0, void 0, function* () {
    // Fetch temporary user data from session or Redis
    const tempUser = yield (0, helper_1.getUserDataFromSession)(email);
    if (!tempUser) {
        (0, createLog_1.default)(JSON.stringify({ Error: 'User data not found' }));
        return;
    }
    try {
        const newUser = new user_1.default(tempUser);
        yield user_1.default.init();
        const user = yield newUser.save();
        // Log the OTP verification activity
        const otpLog = new LogFile_1.default({
            email: tempUser.email,
            ActivityName: 'User Verified OTP',
            AddedOn: date_1.default
        });
        yield otpLog.save();
        // Log the new user creation activity
        const logEntry = new LogFile_1.default({
            fullname: tempUser.fullname,
            email: tempUser.email,
            ActivityName: `New user created with email: ${tempUser.email}`,
            AddedOn: date_1.default
        });
        yield logEntry.save();
        // // Clear temporary user data from session or Redis
        // await deleteUserDataFromSession(req);
        // Clear temporary user data from Redis
        yield redisClient_1.default.del(`${email}_tempUser`);
        // Generate a JWT token for the user
        const token = (0, jwt_1.generateToken)({ email: newUser.email, id: newUser.id });
        // Info level logging
        logger_1.default.info(`User account created. - ${user.email}`, {
            timestamp: new Date().toISOString()
        });
        // Log success
        (0, createLog_1.default)(JSON.stringify({ Success: `User account created for ${user.email}` }));
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
    }
    catch (err) {
        (0, createLog_1.default)(JSON.stringify({ Error: err.message }));
        // Error level logging
        logger_1.default.error(`Error creating User account: ${err.message}`, {
            timestamp: new Date().toISOString()
        });
        // res.status(500).json({
        //   status: '00',
        //   success: true,
        //   message: `Error creating user: ${err.message}`
        // });
    }
});
exports.completeRegistration = completeRegistration;
