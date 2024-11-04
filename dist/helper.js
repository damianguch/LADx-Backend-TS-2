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
exports.deleteOtpDataFromSession = exports.deleteUserDataFromSession = exports.getUserDataFromSession = void 0;
const createLog_1 = __importDefault(require("./utils/createLog"));
const redisClient_1 = __importDefault(require("./utils/redisClient"));
const getUserDataFromSession = (email) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const tempUser = yield redisClient_1.default.get(`${email}_tempUser`);
        if (!tempUser) {
            (0, createLog_1.default)(JSON.stringify({ Error: 'User data not found in Redis' }));
            return null;
        }
        return JSON.parse(tempUser);
    }
    catch (err) {
        (0, createLog_1.default)(JSON.stringify({ Error: `Failed to retrieve user data: ${err.message}` }));
        return null;
    }
});
exports.getUserDataFromSession = getUserDataFromSession;
const deleteUserDataFromSession = (req) => __awaiter(void 0, void 0, void 0, function* () {
    // Remove tempUser data from the session
    if (req.session) {
        delete req.session.tempUser;
    }
});
exports.deleteUserDataFromSession = deleteUserDataFromSession;
const deleteOtpDataFromSession = (req) => __awaiter(void 0, void 0, void 0, function* () {
    // Remove tempUser data from the session
    if (req.session) {
        delete req.session.otpData;
    }
});
exports.deleteOtpDataFromSession = deleteOtpDataFromSession;
