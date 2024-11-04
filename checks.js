// Generating SSL Certificates (for local development):
// To generate self-signed certificates for development purposes, you can use
// openssl:

// openssl genrsa -out privatekey.pem 2048
// openssl req -new -key privatekey.pem -out certrequest.csr
// openssl x509 -req -in certrequest.csr -signkey privatekey.pem -out certificate.pem

// Authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: 'Authorization token required' });
  }
};

// Authentication and Authorization
// Ensure you implement stateless authentication using JWT. Only issue tokens
// after successful login and store them securely.
// Validate JWT on every API request.

// OAuth or OpenID Connect: For advanced, scalable applications, consider
// OAuth2 or OpenID for handling external authentication providers like Google,
// GitHub, etc.

/**
 * Authenticate routes based on JWT
 * The middleware ensures that only authenticated users (users who provide a
 * valid JWT token) can access certain protected routes in the application.
 
   A route with the auth middleware is a protected route that requires 
   authentication.
 * The authenticateJWT middleware is applied, so any request to this route must
 *  include a valid JWT token in the Authorization header. If the token is valid,
 *  the user information will be accessible via req.user.
 */

/**
 * How it Works:
    Extract the Token: The middleware checks the Authorization header of the 
    request. The Authorization header typically contains a Bearer token 
    (formatted as Bearer <JWT>). It splits the string to extract the actual 
    token part.

    Verify the Token: If the token is present, it uses jwt.verify() to validate 
    the token against a secret (process.env.JWT_SECRET). If the token is valid, 
    it decodes the token to retrieve user information.

    Handle Invalid or Missing Tokens: If the token is invalid (e.g., expired, 
    tampered with) or not present, the middleware responds with either a 403 
    Forbidden (invalid token) or 401 Unauthorized (missing token).

    Proceed if Verified: If the token is valid, it attaches the decoded user 
    information to the req object (req.user = user), allowing downstream routes 
    or middleware to access the user’s details. The next() function is called to
     allow the request to proceed to the next middleware or route handler.
 */

/**  Using Cloud Storage (AWS S3)
Below is how you can implement image deletion when using AWS S3.
 - Install AWS SDK:
npm install aws-sdk
*/

//AWS S3 Configuration: Configure the S3 client:
const AWS = require('aws-sdk');
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const User = require('../models/user');
const { createAppLog } = require('../utils/createLog');
const { currentDate } = require('../utils/date');
const multer = require('multer');
const path = require('path');
const AWS = require('aws-sdk');
const s3 = new AWS.S3({
  /* AWS config here */
});

// Configure Multer for local temp storage
const upload = multer({ dest: 'uploads/temp' });

// Function to delete a file from S3
const deleteFromS3 = async (fileKey) => {
  const params = { Bucket: process.env.AWS_S3_BUCKET, Key: fileKey };
  return s3.deleteObject(params).promise();
};

// Function to upload a file to S3
const uploadToS3 = async (file) => {
  const fileContent = fs.readFileSync(file.path);
  const params = {
    Bucket: process.env.AWS_S3_BUCKET,
    Key: `profile-pics/${Date.now()}-${file.originalname}`, // Unique file name
    Body: fileContent,
    ContentType: file.mimetype
  };
  const data = await s3.upload(params).promise();
  return data.Location; // This is the S3 file URL
};

// Update Profile with S3 logic
const UpdateProfile = async (req, res) => {
  const { id } = req.params;
  const { fullname, country, state } = req.body;

  try {
    const user = await User.findById(id);
    if (!user) {
      return res
        .status(404)
        .json({ status: 'E00', message: 'User not found!' });
    }

    const oldProfilePic = user.profilePic;

    const userProfile = { fullname, country, state };

    if (req.file) {
      const newProfilePicUrl = await uploadToS3(req.file);
      userProfile.profilePic = newProfilePicUrl;

      if (oldProfilePic) {
        const oldFileKey = oldProfilePic.split('/').pop(); // Extract S3 key from URL
        await deleteFromS3(oldFileKey);
      }
    }

    await User.findByIdAndUpdate(id, { $set: userProfile });

    res.status(200).json({
      status: '00',
      message: 'Profile updated successfully',
      data: userProfile
    });
  } catch (error) {
    res.status(500).json({ status: 'E00', message: error.message });
  }
};

module.exports = { UpdateProfile };

/** How it Works:
    Upload to S3: The uploadToS3 function reads the file from the temporary 
    directory (where Multer stores it) and uploads it to your S3 bucket. It then 
    returns the file’s URL.
    Delete from S3: The deleteFromS3 function deletes the old image file from S3 
    using its key (the last part of the file URL).
 */

// Generate and send CSRF token
res.cookie('csrfToken', req.csrfToken(), {
  httpOnly: false, // CSRF token must be accessible by client-side scripts
  secure: true, // use true in production
  sameSite: 'Strict'
});

// OTP Verification route
const verifyOTP = async (req, res) => {
  const { otp } = req.body;

  if (!otp) {
    return res.status(400).json({ message: 'OTP is required' });
  }

  try {
    const storedOTP = otpStore['email'];
    const storedEmail = emailStore['email'];

    const user = await User.findOne({ email: storedEmail });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    if (!storedOTP) {
      return res.status(400).json({ message: 'OTP not found ' });
    }

    const isMatch = await bcrypt.compare(otp, storedOTP);
    if (isMatch) {
      user.is_email_verified = 1;
      await user.save();

      // Remove OTP/email after successful verification
      delete otpStore['email'];
      delete emailStore['email'];

      // log data
      await createAppLog(JSON.stringify('OTP verified successfully!'));

      // Log the verification activity
      const log = new LogFile({
        email: user.email,
        ActivityName: 'User Verified OTP',
        AddedOn: currentDate
      });

      await log.save();

      return res.status(200).json({ message: 'OTP verified successfully!' });
    } else {
      await createAppLog(JSON.stringify('Invalid OTP'));
      return res.status(400).json({ message: 'Invalid OTP' });
    }
  } catch (error) {
    createAppLog(JSON.stringify('OTP Verification Error!'));
    return res.status(500).json({ message: 'Internal Server Error!' });
  }
};

// To append new images instead
requestDetails.requestItemsUrls = [
  ...requestDetails.requestItemsUrls,
  ...newImageUrls
];

// Update other request details fields if provided
requestDetails.package_details =
  package_details || requestDetails.package_details;
requestDetails.package_name = package_name || requestDetails.package_name;
requestDetails.item_description =
  item_description || requestDetails.item_description;
requestDetails.package_value = package_value || requestDetails.package_value;
requestDetails.quantity = quantity || requestDetails.quantity;
requestDetails.price = price || requestDetails.price;
requestDetails.address_from = address_from || requestDetails.address_from;
requestDetails.address_to = address_to || requestDetails.address_to;
requestDetails.reciever_name = reciever_name || requestDetails.reciever_name;
requestDetails.reciever_phone_number =
  reciever_phone_number || requestDetails.reciever_phone_number;

// Save the updated request details to the database
await requestDetails.save();

// Store OTP in a map with an expiration time
otpStore.set(email, { hashedOTP, expiresAt: Date.now() + 60 * 60 * 1000 });
// Store temp user in memory
otpStore.set(`${email}_tempUser`, tempUser);
