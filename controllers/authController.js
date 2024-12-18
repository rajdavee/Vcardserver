  const User = require('../models/User');
  const jwt = require('jsonwebtoken');
  const sendEmail = require('../utils/sendEmail');
  const vCardsJS = require('vcards-js');
  const multer = require('multer');
  const fs = require('fs-extra');
  const QRCode = require('qrcode');
  const vCard = require('vcf');
  const ejs = require('ejs');
  const path = require('path');
  const crypto = require('crypto');
  const VCardScan = require('../models/VCardScan');
  const axios = require('axios');
  const mongoose = require('mongoose');
  const cloudinary = require('../config/cloudinaryConfig');
  const { getLocationData } = require('../utils/geolocation');
  const fetch = require('node-fetch');
  const requestIp = require('request-ip');
  const FormSubmission = require('../models/FormSubmission');

// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  Helper functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
const uploadImage = async (file) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  const maxSize = 5 * 1024 * 1024; // 5MB

  if (!allowedTypes.includes(file.mimetype)) {
    throw new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.');
  }

  if (file.size > maxSize) {
    throw new Error('File size exceeds the 5MB limit.');
  }

  try {
    const result = await cloudinary.uploader.upload(file.tempFilePath, {
      folder: 'vcard_images',
      use_filename: true,
      unique_filename: true,
    });
    return result.secure_url;
  } catch (error) {
    console.error('Error uploading to Cloudinary:', error);
    throw new Error('Failed to upload image');
  }
};

async function generateQRCode(vCardData) {
  try {
    const getField = (fieldName) => {
      const field = vCardData.fields.find(f => f.name === fieldName);
      return field ? field.value.toString().trim() : '';
    };

    // Ensure proper encoding of special characters
    const encodeField = (value) => {
      if (!value) return '';
      return value
        .replace(/\\/g, '\\\\')
        .replace(/;/g, '\\;')
        .replace(/,/g, '\\,')
        .replace(/\n/g, '\\n');
    };

    // Debug log to check fields
    console.log('Incoming vCard fields:', vCardData.fields);

    // Build name components
    const firstName = getField('firstName');
    const lastName = getField('lastName');
    const fullName = getField('name') || `${firstName} ${lastName}`.trim();
    const company = getField('companyName') || getField('company'); // Try both field names

    const vCardLines = [
      'BEGIN:VCARD',
      'VERSION:3.0',
      // Name fields - properly encoded
      `FN:${encodeField(fullName)}`,
      `N:${encodeField(lastName)};${encodeField(firstName)};;;`,
      
      // Organization and title - ensure company name is included
      company ? `ORG:${encodeField(company)}` : '',
      getField('jobTitle') ? `TITLE:${encodeField(getField('jobTitle'))}` : '',
      
      // Contact numbers - ensure proper formatting
      getField('phone') ? `TEL;TYPE=WORK,VOICE:${getField('phone').replace(/[^+0-9]/g, '')}` : '',
      getField('mobile') ? `TEL;TYPE=CELL,VOICE:${getField('mobile').replace(/[^+0-9]/g, '')}` : '',
      
      // Email and website - ensure website is included
      getField('email') ? `EMAIL;TYPE=WORK,INTERNET:${encodeField(getField('email'))}` : '',
      getField('website') ? `URL:${encodeField(getField('website'))}` : '',
      
      // Full address with all components
      (getField('address') || getField('city') || getField('state') || getField('country')) ? 
        `ADR;TYPE=WORK:;;${[
          encodeField(getField('address')),
          encodeField(getField('city')),
          encodeField(getField('state')),
          encodeField(getField('postalCode')),
          encodeField(getField('country'))
        ].join(';')}` : '',
      
      // Social profiles
      getField('linkedin') ? `X-SOCIALPROFILE;TYPE=linkedin:${encodeField(getField('linkedin'))}` : '',
      getField('twitter') ? `X-SOCIALPROFILE;TYPE=twitter:${encodeField(getField('twitter'))}` : '',
      
      // Notes
      getField('note') ? `NOTE:${encodeField(getField('note'))}` : '',
      'END:VCARD'
    ].filter(line => line);

    const vCard = vCardLines.join('\r\n');
    
    // Debug log to check final vCard string
    console.log('Generated vCard string:', vCard);

    const qrCodeDataUrl = await QRCode.toDataURL(vCard, {
      errorCorrectionLevel: 'Q',
      type: 'image/png',
      quality: 1.0,
      margin: 4,
      width: 1024,
      rendererOpts: {
        quality: 1.0
      }
    });

    return { qrCodeDataUrl, vCardString: vCard };
  } catch (error) {
    console.error('Error generating QR code:', error);
    throw error;
  }
}
async function generateAndSaveQRCode(vCardId, user, vCardIndex) {
  try {
    const scanUrl = `${process.env.FRONTEND_URL}/api/scan/${vCardId}`;
    const qrCodeDataUrl = await QRCode.toDataURL(scanUrl);
    user.vCards[vCardIndex].qrCode = qrCodeDataUrl;
    await user.save();
    return qrCodeDataUrl;
  } catch (error) {
    console.error('Error generating QR code:', error);
    throw error;
  }
}
function generateVCardString(vCardData) {
  const fieldMap = new Map(vCardData.fields.map(f => [f.name, f.value]));
  
  // Build MECARD format string (more compatible with mobile devices)
  let mecard = [];
  
  // Name (required)
  const fullName = fieldMap.get('name') || `${fieldMap.get('firstName') || ''} ${fieldMap.get('lastName') || ''}`.trim();
  mecard.push(`N:${fullName}`);
  
  // Phone
  if (fieldMap.has('phone')) {
    mecard.push(`TEL:${fieldMap.get('phone')}`);
  }
  
  // Email
  if (fieldMap.has('email')) {
    mecard.push(`EMAIL:${fieldMap.get('email')}`);
  }
  
  // Website
  if (fieldMap.has('website')) {
    mecard.push(`URL:${fieldMap.get('website')}`);
  }
  
  // Company
  if (fieldMap.has('company')) {
    mecard.push(`ORG:${fieldMap.get('company')}`);
  }
  
  // Job Title
  if (fieldMap.has('jobTitle')) {
    mecard.push(`TITLE:${fieldMap.get('jobTitle')}`);
  }
  
  // Address
  const addressParts = [];
  if (fieldMap.has('address')) addressParts.push(fieldMap.get('address'));
  if (fieldMap.has('city')) addressParts.push(fieldMap.get('city'));
  if (fieldMap.has('state')) addressParts.push(fieldMap.get('state'));
  if (fieldMap.has('postalCode')) addressParts.push(fieldMap.get('postalCode'));
  if (fieldMap.has('country')) addressParts.push(fieldMap.get('country'));
  
  if (addressParts.length > 0) {
    mecard.push(`ADR:${addressParts.join(',')}`);
  }
  
  // Note (can include additional information)
  if (fieldMap.has('note')) {
    mecard.push(`NOTE:${fieldMap.get('note')}`);
  }
  
  // Join all fields with semicolons
  return mecard.join(';');
}
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  Auth functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
exports.register = async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // Check for valid username (minimum 3 characters, no special characters)
      const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
      if (!usernameRegex.test(username) || username.trim() === '') {
        return res.status(400).json({ error: 'Invalid username format' });
      }

      // Check for missing required fields
      if (!email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
      }

      // Check for invalid email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }

      // Check for weak password (minimum 8 characters)
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password is too weak. It must be at least 8 characters long' });
      }

      // Sanitize password to prevent SQL injection attempts
      const passwordRegex = /^[a-zA-Z0-9!@#$%^&*()_+<>?]{8,}$/; // Adjust the regex as necessary
      if (!passwordRegex.test(password)) {
        return res.status(400).json({ error: 'Invalid password format' });
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // Create verification token
      const verificationToken = crypto.randomBytes(20).toString('hex');
      const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

      // Create new user
      const user = new User({
        username,
        email,
        password, // Password hashing will be handled by the pre('save') middleware in the schema
        verificationToken,
        verificationExpires,
        isVerified: false,
        role: 'user' // Default role
      });

      // Save user to database
      try {
        await user.save();
      } catch (saveError) {
        if (saveError.code === 11000) { // MongoDB duplicate key error
          return res.status(400).json({ error: 'User already exists' });
        }
        throw saveError; // Re-throw other errors
      }

      // Check if token is expired (this is unlikely to happen immediately after creation, but included for completeness)
      if (user.verificationExpires < Date.now()) {
        await User.deleteOne({ _id: user._id });
        return res.status(400).json({ error: 'Verification token expired' });
      }

      // Generate verification URL
      const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

      // Send verification email
      try {
        await sendEmail({
          to: user.email,
          subject: 'Email Verification',
          text: `Please click on the following link to verify your email: ${verificationUrl}`,
          html: `<p>Please click on the following link to verify your email:</p><p><a href="${verificationUrl}">${verificationUrl}</a></p>`
        });
      } catch (emailError) {
        // Handle email sending failure
        console.error('Email sending error:', emailError);
        await User.deleteOne({ _id: user._id }); // Rollback user creation if email fails
        return res.status(500).json({ error: 'Email sending failed. Please try again later.' });
      }

      res.status(201).json({
        message: 'User registered successfully. Please check your email to verify your account.',
        userId: user._id
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed. Please try again later.' });
    }
};
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check for missing email or password
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: 'Please verify your email before logging in' });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
};
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Check for missing email
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // Token expires in 10 minutes
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    const message = `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\nPlease click on the following link, or paste this into your browser to complete the process:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.`;

    try {
      await sendEmail({
        to: user.email,
        subject: 'Password Reset Request',
        text: message,
      });

      res.status(200).json({ message: 'Password reset email sent' });
    } catch (error) {
      console.error('Send email error:', error);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      return res.status(500).json({ error: 'Error sending password reset email' });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};
exports.resetPassword = async (req, res) => {
  try {
    console.log('Reset password request body:', req.body);
    console.log('Reset password token from params:', req.params.token);
    
    const { token } = req.params;
    const { password } = req.body;

    // Check if password is missing or empty
    if (!password || password.trim() === '') {
      return res.status(400).json({ error: 'Password is required' });
    }

    // Check for weak password (minimum 8 characters)
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password is too weak. It must be at least 8 characters long' });
    }

    // Sanitize password to prevent SQL injection attempts
    const passwordRegex = /^[a-zA-Z0-9!@#$%^&*()_+<>?]{8,}$/; // Adjust the regex as necessary
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ error: 'Invalid password format' });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
    });

    if (!user) {
      return res.status(400).json({ error: 'Password reset token is invalid or has expired' });
    }

    // Explicitly check if the token has expired
    if (user.resetPasswordExpires < Date.now()) {
      return res.status(400).json({ error: 'Password reset token is invalid or has expired' });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password has been reset' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Error resetting password' });
  }
};
exports.checkVerificationStatus = async (req, res) => {
  try {
    if (!req.user || !req.user.userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ isVerified: user.isVerified });
  } catch (error) {
    console.error('Check verification status error:', error);
    res.status(500).json({ error: 'Error checking verification status' });
  }
};
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }

    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    if (user.verificationExpires < Date.now()) {
      return res.status(400).json({ error: 'Verification token has expired' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully. You can now log in.' });
  } catch (error) {
    console.error('Email verification error:', error);
    if (error.name === 'MongoError' || error.name === 'MongooseError') {
      return res.status(500).json({ error: 'Database error occurred' });
    }
    res.status(500).json({ error: 'Email verification failed' });
  }
};
exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    // Check if a minute has passed since the last verification email
    if (user.lastVerificationSent && Date.now() - user.lastVerificationSent < 60000) {
      return res.status(400).json({ error: 'Please wait a minute before requesting a new verification email' });
    }

    // Create new verification token
    user.verificationToken = crypto.randomBytes(20).toString('hex');
    user.verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    user.lastVerificationSent = Date.now();
    await user.save();

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${user.verificationToken}`;
    const message = `Please click on the following link to verify your email: ${verificationUrl}`;

    await sendEmail({
      to: user.email,
      subject: 'Email Verification',
      text: message,
    });

    res.json({ message: 'Verification email sent. Please check your inbox.' });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Failed to resend verification email' });
  }
};
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  User functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: 'Error fetching user data' });
  }
};
exports.getUserPlan = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ planName: user.plan?.name || 'Free' });
  } catch (error) {
    console.error('Get user plan error:', error);
    res.status(500).json({ error: 'Error fetching user plan' });
  }
};
exports.getUserInfo = async (req, res) => {
  console.log('getUserInfo function called');
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      console.log('User not found');
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('User info retrieved:', JSON.stringify(user, null, 2));
    res.json({
      username: user.username,
      email: user.email,
      plan: {
        name: user.plan?.name,
        availableTemplates: user.plan?.availableTemplates,
        price: user.plan?.price,
        subscribedAt: user.plan?.subscribedAt
      }
    });
  } catch (error) {
    console.error('Get user info error:', error);
    res.status(500).json({ error: 'Error fetching user info' });
  }
};
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  vCard functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------

exports.getPublicVCardPreview = async (req, res) => {
  try {
    const { vCardId } = req.params;
    console.log(`Fetching public vCard preview with id: ${vCardId}`);
    
    const user = await User.findOne({ 'vCards._id': vCardId });
    
    if (!user) {
      console.log(`vCard not found for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(vCardId);
    
    if (!vCard) {
      console.log(`vCard not found in user document for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    console.log(`Successfully fetched public vCard for preview: ${JSON.stringify(vCard)}`);

    // Send the vCard data as JSON without the QR code
    res.json({
      templateId: vCard.templateId,
      fields: vCard.fields
    });
  } catch (error) {
    console.error('Error fetching public vCard preview:', error);
    res.status(500).json({ error: 'Error fetching vCard preview', details: error.message });
  }
};
exports.getVCardPreview = async (req, res) => {
  try {
    const { vCardId } = req.params;
    console.log(`Fetching vCard preview for id: ${vCardId}`);

    const user = await User.findOne({ 'vCards._id': vCardId });
    if (!user) {
      console.log(`vCard not found for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(vCardId);
    if (!vCard) {
      console.log(`vCard not found in user document for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    console.log(`Successfully fetched vCard for preview: ${JSON.stringify(vCard)}`);

    res.json({
      templateId: vCard.templateId,
      fields: vCard.fields,
      qrCodeDataUrl: vCard.qrCode
    });
  } catch (error) {
    console.error('Error getting vCard preview:', error);
    res.status(500).json({ error: 'Error getting vCard preview' });
  }
};

exports.createVCard = async (req, res) => {
  try {
    const { userId } = req.user;
    const { templateId, fields } = JSON.parse(req.body.data);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const newVCard = {
      templateId,
      fields
    };

    // Handle file upload if present
    if (req.files && req.files.profileImage) {
      try {
        const imagePath = await uploadImage(req.files.profileImage);
        newVCard.fields.push({ name: 'profileImage', value: imagePath });
      } catch (uploadError) {
        return res.status(400).json({ error: uploadError.message });
      }
    }

    const { qrCodeDataUrl, vCardString } = await generateQRCode(newVCard);
    
    const vCardId = new mongoose.Types.ObjectId();
    user.vCards.push({
      _id: vCardId,
      ...newVCard,
      qrCode: qrCodeDataUrl,
      vCardString: vCardString
    });

    await user.save();

    res.status(201).json({
      message: 'vCard created successfully',
      vCardId: vCardId.toString(),
      qrCodeDataUrl: qrCodeDataUrl,
      vCardString: vCardString,
      previewLink: `${process.env.FRONTEND_URL}/preview?vCardId=${vCardId.toString()}`
    });
  } catch (error) {
    console.error('Error creating vCard:', error);
    res.status(500).json({ error: 'Error creating vCard', details: error.message });
  }
};
exports.updateVCard = async (req, res) => {
  try {
    const { userId } = req.user;
    const { vCardId } = req.params;
    
    console.log('Received request body:', req.body);
    
    let templateId, fields;
    
    if (typeof req.body === 'object' && req.body !== null) {
      // If the body is already an object, use it directly
      ({ templateId, fields } = req.body);
    } else if (typeof req.body.data === 'string') {
      // If the data is a string, parse it
      ({ templateId, fields } = JSON.parse(req.body.data));
    } else {
      throw new Error('Invalid request body format');
    }

    if (!templateId || !fields) {
      throw new Error('Missing required fields');
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const vCardIndex = user.vCards.findIndex(card => card._id.toString() === vCardId);
    if (vCardIndex === -1) {
      return res.status(404).json({ error: 'vCard not found' });
    }

    // Handle file upload if present
    if (req.files && req.files.profileImage) {
      try {
        const imagePath = await uploadImage(req.files.profileImage);
        
        // Remove old image from Cloudinary if it exists
        const oldImageField = fields.find(field => field.name === 'profileImage');
        if (oldImageField) {
          const oldPublicId = oldImageField.value.split('/').pop().split('.')[0];
          await cloudinary.uploader.destroy(`vcard_images/${oldPublicId}`);
        }

        fields = fields.filter(field => field.name !== 'profileImage');
        fields.push({ name: 'profileImage', value: imagePath });
      } catch (uploadError) {
        return res.status(400).json({ error: uploadError.message });
      }
    }

    user.vCards[vCardIndex].templateId = templateId;
    user.vCards[vCardIndex].fields = fields;

    const { qrCodeDataUrl, vCardString } = await generateQRCode(user.vCards[vCardIndex]);
    user.vCards[vCardIndex].qrCode = qrCodeDataUrl;
    user.vCards[vCardIndex].vCardString = vCardString;

    await user.save();

    res.json({
      message: 'vCard updated successfully',
      qrCodeDataUrl: qrCodeDataUrl,
      vCardString: vCardString,
      previewLink: `${process.env.FRONTEND_URL}/preview?vCardId=${vCardId}`
    });
  } catch (error) {
    console.error('Error updating vCard:', error);
    res.status(500).json({ error: 'Error updating vCard', details: error.message });
  }
};
exports.uploadChunk = async (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files were uploaded.');
  }

  const { chunk } = req.files;
  const { fileName, chunkIndex, totalChunks } = req.body;

  try {
    const result = await cloudinary.uploader.upload(chunk.tempFilePath, {
      resource_type: 'video',
      folder: 'vcard_videos',
      public_id: `${fileName}_chunk_${chunkIndex}`,
      use_filename: true,
      unique_filename: false,
    });

    if (parseInt(chunkIndex) === parseInt(totalChunks) - 1) {
      // All chunks uploaded, create the final video
      const chunkUrls = [];
      for (let i = 0; i < totalChunks; i++) {
        const chunkResult = await cloudinary.api.resource(`vcard_videos/${fileName}_chunk_${i}`, { resource_type: 'video' });
        chunkUrls.push(chunkResult.secure_url);
      }

      // Use Cloudinary's API to concatenate video chunks
      const finalResult = await cloudinary.uploader.upload(chunkUrls.join('|'), {
        resource_type: 'video',
        folder: 'vcard_videos',
        public_id: fileName,
        use_filename: true,
        unique_filename: false,
      });

      // Clean up chunk files
      for (let i = 0; i < totalChunks; i++) {
        await cloudinary.uploader.destroy(`vcard_videos/${fileName}_chunk_${i}`, { resource_type: 'video' });
      }

      res.send({ message: 'File upload completed', filePath: finalResult.secure_url });
    } else {
      res.send('Chunk received');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send(err);
  }
};
exports.getVCards = async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId).select('vCards');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      vCards: user.vCards || [],
      count: user.vCards.length
    });
  } catch (error) {
    console.error('Error fetching vCards:', error);
    res.status(500).json({ error: 'Failed to fetch vCards' });
  }
};
exports.deleteVCard = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const userId = req.user.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const vCardIndex = user.vCards.findIndex(card => card._id.toString() === vCardId);
    if (vCardIndex === -1) {
      return res.status(404).json({ error: 'vCard not found' });
    }

    user.vCards.splice(vCardIndex, 1);
    await user.save();

    res.json({ message: 'vCard deleted successfully' });
  } catch (error) {
    console.error('Error deleting vCard:', error);
    res.status(500).json({ error: 'Error deleting vCard', details: error.message });
  }
};
exports.getVCard = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const userId = req.user.userId;
    console.log(`Fetching vCard ${vCardId} for user ${userId}`);

    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    
    if (!user) {
      console.log(`User or vCard not found for userId: ${userId}, vCardId: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(vCardId);
    if (!vCard) {
      console.log(`vCard not found in user document for vCardId: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found in user document' });
    }

    console.log(`Successfully fetched vCard: ${JSON.stringify(vCard)}`);
    res.json({
      ...vCard.toObject(),
      qrCodeDataUrl: vCard.qrCode
    });
  } catch (error) {
    console.error('Error fetching vCard:', error);
    res.status(500).json({ error: 'Error fetching vCard', details: error.message });
  }
};
exports.getPublicVCard = async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Fetching public vCard with id: ${id}`);
    
    const user = await User.findOne({ 'vCards._id': id });
    
    if (!user) {
      console.log(`vCard not found for id: ${id}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(id);
    
    if (!vCard) {
      console.log(`vCard not found in user document for id: ${id}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    console.log(`Successfully fetched public vCard: ${JSON.stringify(vCard)}`);
    res.json({
      ...vCard.toObject(),
      qrCodeDataUrl: vCard.qrCode
    });
  } catch (error) {
    console.error('Error fetching public vCard:', error);
    res.status(500).json({ error: 'Error fetching vCard' });
  }
};
exports.submitForm = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { name, email, phone, message } = req.body;

    // Validate required fields
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'Name, email, and message are required fields' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Create new form submission
    const formSubmission = new FormSubmission({
      vCardId,
      submitterName: name,
      submitterEmail: email,
      submitterPhone: phone,
      message
    });

    await formSubmission.save();

    res.status(201).json({
      message: 'Form submitted successfully',
      submissionId: formSubmission._id
    });
  } catch (error) {
    console.error('Error submitting form:', error);
    res.status(500).json({ error: 'Error submitting form', details: error.message });
  }
};
exports.getFormSubmissions = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { userId } = req.user;

    // Verify that the vCard belongs to the user
    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    if (!user) {
      return res.status(404).json({ error: 'vCard not found or does not belong to the user' });
    }

    const submissions = await FormSubmission.find({ vCardId })
      .sort({ submittedAt: -1 }); // Most recent first

    res.json({
      total: submissions.length,
      submissions
    });
  } catch (error) {
    console.error('Error fetching form submissions:', error);
    res.status(500).json({ error: 'Error fetching form submissions', details: error.message });
  }
};

// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  Analytics functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------


async function getIpAndLocationData(req) {
  try {
    const clientIp = requestIp.getClientIp(req);
    console.log(`Detected client IP: ${clientIp}`);

    // Use a fallback IP if the detected IP is a local address
    const ipToUse = clientIp === '::1' || clientIp === '127.0.0.1' 
      ? '8.8.8.8'  // Google's public DNS as a fallback
      : clientIp;

    const response = await axios.get(`https://ipapi.co/${ipToUse}/json/`);
    const locationData = response.data;

    if (locationData.error) {
      throw new Error(locationData.reason || 'Error fetching location data');
    }

    return {
      ipAddress: clientIp,
      location: {
        city: locationData.city,
        region: locationData.region,
        country: locationData.country_name,
        latitude: locationData.latitude,
        longitude: locationData.longitude
      },
      fullData: locationData
    };
  } catch (error) {
    console.error('Error in IP detection and location service:', error);
    throw error;
  }
}
exports.handleScan = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const userAgent = req.headers['user-agent'];

    // Use the combined function to get IP and location data
    const { ipAddress, location, fullData } = await getIpAndLocationData(req);

    // Determine device type
    const isMobile = /mobile/i.test(userAgent);
    const device = isMobile ? 'Mobile' : 'Desktop';

    // Find or create VCardScan document
    let vCardScan = await VCardScan.findOne({ vCardId });
    if (!vCardScan) {
      vCardScan = new VCardScan({ vCardId, scans: [] });
    }

    // Check if this IP has already been recorded
    const existingScan = vCardScan.scans.find(scan => scan.ipAddress === ipAddress);

    if (!existingScan) {
      // This is a new unique IP
      const newScan = {
        ipAddress,
        userAgent,
        scanDate: new Date(),
        location: {
          latitude: location.latitude,
          longitude: location.longitude,
          city: location.city,
          country: location.country
        },
        device,
        scanType: req.query.scanType || 'QR' // Default to 'QR' if not specified
      };

      // Add the new scan to the scans array
      vCardScan.scans.push(newScan);

      // Increment the appropriate counter
      switch (newScan.scanType) {
        case 'QR':
          vCardScan.qrScans += 1;
          break;
        case 'Link':
          vCardScan.linkClicks += 1;
          break;
        case 'Preview':
          vCardScan.previewClicks += 1;
          break;
      }

      await vCardScan.save();

      res.status(200).json({ 
        message: 'New unique scan recorded successfully', 
        scanId: newScan._id,
        isNewScan: true
      });
    } else {
      // This IP has already been recorded
      // Update the last scan date for this IP
      existingScan.scanDate = new Date();
      await vCardScan.save();

      res.status(200).json({ 
        message: 'Scan from this IP already recorded', 
        isNewScan: false
      });
    }

    // Optionally, update the lastAccessed field of the vCard
    // You'll need to ensure this field exists in your User model
    const user = await User.findOne({ 'vCards._id': vCardId });
    if (user) {
      const vCard = user.vCards.id(vCardId);
      if (vCard) {
        vCard.lastAccessed = new Date();
        await user.save();
      }
    }

  } catch (error) {
    console.error('Error handling scan:', error);
    res.status(500).json({ error: 'Failed to record scan', details: error.message });
  }
};
exports.getVCardAnalytics = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { userId } = req.user;

    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    if (!user) {
      return res.status(404).json({ error: 'vCard not found or does not belong to the user' });
    }

    const vCardScan = await VCardScan.findOne({ vCardId });
    if (!vCardScan) {
      return res.json({
        totalScans: 0,
        qrScans: 0,
        linkClicks: 0,
        previewClicks: 0,
        recentScans: [],
        locationBreakdown: {},
        deviceBreakdown: {},
        timeBreakdown: {}
      });
    }

    const scans = vCardScan.scans;

    const analytics = {
      totalScans: scans.length,
      qrScans: vCardScan.qrScans,
      linkClicks: vCardScan.linkClicks,
      previewClicks: vCardScan.previewClicks,
      recentScans: scans.slice(-10).reverse().map(scan => ({
        scanDate: scan.scanDate,
        location: {
          city: scan.location?.city || 'Unknown',
          country: scan.location?.country || 'Unknown'
        },
        device: scan.device,
        scanType: scan.scanType
      })),
      locationBreakdown: {},
      deviceBreakdown: {},
      timeBreakdown: {
        hourly: Array(24).fill(0),
        daily: Array(7).fill(0),
        monthly: Array(12).fill(0)
      }
    };

    scans.forEach(scan => {
      // Location breakdown
      const country = scan.location?.country || 'Unknown';
      analytics.locationBreakdown[country] = (analytics.locationBreakdown[country] || 0) + 1;

      // Device breakdown
      analytics.deviceBreakdown[scan.device] = (analytics.deviceBreakdown[scan.device] || 0) + 1;

      // Time breakdown
      const scanDate = new Date(scan.scanDate);
      analytics.timeBreakdown.hourly[scanDate.getHours()]++;
      analytics.timeBreakdown.daily[scanDate.getDay()]++;
      analytics.timeBreakdown.monthly[scanDate.getMonth()]++;
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching vCard analytics:', error);
    res.status(500).json({ error: 'Error fetching vCard analytics', details: error.message });
  }
};
exports.getVCardScanAnalytics = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { userId } = req.user;

    // Check if the vCard belongs to the user
    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    if (!user) {
      return res.status(404).json({ error: 'vCard not found or does not belong to the user' });
    }

    const vCardScan = await VCardScan.findOne({ vCardId });
    if (!vCardScan) {
      return res.json({ totalScans: 0, recentScans: [], locationBreakdown: {}, deviceBreakdown: {} });
    }

    const scans = vCardScan.scans;

    const analytics = {
      totalScans: scans.length,
      recentScans: scans.slice(-10).reverse().map(scan => ({
        scanDate: scan.scanDate,
        location: {
          city: scan.location.city || 'Unknown',
          country: scan.location.country || 'Unknown'
        }
      })),
      locationBreakdown: {},
      deviceBreakdown: {}
    };

    scans.forEach(scan => {
      // Location breakdown
      const country = scan.location.country || 'Unknown';
      analytics.locationBreakdown[country] = (analytics.locationBreakdown[country] || 0) + 1;

      // Device breakdown
      const device = scan.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop';
      analytics.deviceBreakdown[device] = (analytics.deviceBreakdown[device] || 0) + 1;
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching vCard scan analytics:', error);
    res.status(500).json({ error: 'Error fetching vCard scan analytics' });
  }
};
exports.getUserScanAnalytics = async (req, res) => {
  try {
    const { userId } = req.user;

    const user = await User.findById(userId).select('vCards._id');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const vCardIds = user.vCards.map(vCard => vCard._id);
    const vCardScans = await VCardScan.find({ vCardId: { $in: vCardIds } });

    const analytics = {
      totalScans: 0,
      scansByVCard: {},
      overallLocationBreakdown: {},
      overallDeviceBreakdown: {}
    };

    vCardScans.forEach(vCardScan => {
      const scans = vCardScan.scans;
      analytics.totalScans += scans.length;
      analytics.scansByVCard[vCardScan.vCardId] = scans.length;

      scans.forEach(scan => {
        // Overall location breakdown
        const country = scan.location.country || 'Unknown';
        analytics.overallLocationBreakdown[country] = (analytics.overallLocationBreakdown[country] || 0) + 1;

        // Overall device breakdown
        const device = scan.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop';
        analytics.overallDeviceBreakdown[device] = (analytics.overallDeviceBreakdown[device] || 0) + 1;
      });
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching user scan analytics:', error);
    res.status(500).json({ error: 'Error fetching user scan analytics' });
  }
};
exports.recordTimeSpent = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { timeSpent } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();

    console.log(`Recording time spent for vCardId: ${vCardId}`);
    console.log('Time spent:', timeSpent);
    console.log('IP Address:', ip);

    let vCardScan = await VCardScan.findOne({ vCardId });

    if (!vCardScan) {
      console.log(`No VCardScan found for vCardId: ${vCardId}`);
      return res.status(404).json({ error: 'VCard scan record not found' });
    }

    // Find the most recent scan for this IP within the last 24 hours
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const lastScan = vCardScan.scans.find(scan => 
      scan.ipAddress === ip && scan.scanDate > twentyFourHoursAgo
    );
    
    if (lastScan) {
      // Convert timeSpent from seconds to minutes and round to 2 decimal places
      const timeSpentMinutes = Math.round((timeSpent / 60) * 100) / 100;
      // Update the timeSpent field
      lastScan.timeSpent = timeSpentMinutes;
      await vCardScan.save();

      console.log(`Time spent recorded for vCard ${vCardId}: ${lastScan.timeSpent} minutes`);
      res.status(200).json({ message: 'Time spent recorded successfully' });
    } else {
      console.log(`No recent scan found for vCardId: ${vCardId} and IP: ${ip}`);
      res.status(404).json({ error: 'No recent scan found for this vCard and IP' });
    }
  } catch (error) {
    console.error('Error recording time spent:', error);
    res.status(500).json({ error: 'Error recording time spent', details: error.message });
  }
};


// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  Misc functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------


exports.testGeolocation = async (req, res) => {
  try {
    const testIp = req.query.ip || '8.8.8.8'; // Use Google's public DNS as a default test IP
    console.log(`Testing geolocation for IP: ${testIp}`);

    const locationData = await getLocationData(testIp);

    res.json({
      success: true,
      message: 'Geolocation data retrieved successfully',
      data: {
        ip: testIp,
        ...locationData
      }
    });
  } catch (error) {
    console.error('Error testing geolocation:', error);
    res.status(500).json({ success: false, error: 'Error testing geolocation' });
  }
};
exports.handleQRScan = async (req, res) => {

  // This function will be implemented later
  res.status(501).json({ message: 'QR scan functionality not implemented yet' });
};
exports.testUserIpDetection = async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req);
    
    console.log(`Detected client IP: ${clientIp}`);

    // Use the detected IP to fetch location data
    const response = await axios.get(`https://ipapi.co/${clientIp}/json/`);
    const locationData = response.data;

    if (locationData.error) {
      throw new Error(locationData.reason || 'Error fetching location data');
    }

    res.json({
      success: true,
      message: `Your IP address is ${clientIp}`,
      ipAddress: clientIp,
      location: {
        city: locationData.city,
        region: locationData.region,
        country: locationData.country_name,
        latitude: locationData.latitude,
        longitude: locationData.longitude
      },
      fullData: locationData
    });
  } catch (error) {
    console.error('Error in user IP detection service:', error);
    res.status(500).json({ success: false, error: 'Error detecting user IP or fetching location data' });
  }
};

exports.testLocationSpecificService = async (req, res) => {
  try {
    const ip = req.query.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log(`Testing location specific service for IP: ${ip}`);

    const response = await axios.get(`https://ipapi.co/${ip}/json/`);
    const fetchData = response.data;

    if (fetchData.error) {
      throw new Error(fetchData.reason || 'Error fetching location data');
    }

    res.json({
      success: true,
      message: `You are from ${fetchData.region}, ${fetchData.country_name}`,
      data: fetchData
    });
  } catch (error) {
    console.error('Error in location specific service:', error);
    res.status(500).json({ success: false, error: 'Error fetching location data' });
  }
};



module.exports = exports; 
