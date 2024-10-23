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
  const vCardString = generateVCardString(vCardData);
  const qrCodeDataUrl = await QRCode.toDataURL(`${process.env.FRONTEND_URL}/add-contact?vCardData=${encodeURIComponent(vCardString)}`);
  return { qrCodeDataUrl, vCardString };
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
  let vCard = `BEGIN:VCARD\nVERSION:3.0\n`;
  const fieldMap = new Map(vCardData.fields.map(f => [f.name, f.value]));

  // Name
  const fullName = fieldMap.get('name') || `${fieldMap.get('firstName') || ''} ${fieldMap.get('lastName') || ''}`.trim();
  vCard += `FN:${fullName}\n`;
  vCard += `N:${fullName.split(' ').reverse().join(';')};;;\n`;

  if (fieldMap.has('phone')) vCard += `TEL;TYPE=CELL:${fieldMap.get('phone')}\n`;
  if (fieldMap.has('email')) vCard += `EMAIL:${fieldMap.get('email')}\n`;
  if (fieldMap.has('website')) vCard += `URL:${fieldMap.get('website')}\n`;
  if (fieldMap.has('jobTitle')) vCard += `TITLE:${fieldMap.get('jobTitle')}\n`;
  if (fieldMap.has('company')) vCard += `ORG:${fieldMap.get('company')}\n`;

  const address = [fieldMap.get('address'), fieldMap.get('city'), fieldMap.get('postalCode')].filter(Boolean).join(', ');
  if (address) vCard += `ADR:;;${address};;;;\n`;

  vCard += `END:VCARD`;
  return vCard;
}

async function generateQRCode(vCardData) {
  const vCardString = generateVCardString(vCardData);
  const qrCodeDataUrl = await QRCode.toDataURL(`${process.env.FRONTEND_URL}/add-contact?vCardData=${encodeURIComponent(vCardString)}`);
  return { qrCodeDataUrl, vCardString };
}






























































// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  Auth functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
exports.register = async (req, res) => {
  try {
    console.log('Register request body:', req.body);
    const { username, email, password } = req.body;
    
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create verification token
    const verificationToken = crypto.randomBytes(20).toString('hex');
    const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    user = new User({
      username,
      email,
      password,
      verificationToken,
      verificationExpires,
      isVerified: false
    });
    await user.save();

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    const message = `Please click on the following link to verify your email: ${verificationUrl}`;

    await sendEmail({
      to: user.email,
      subject: 'Email Verification',
      text: message,
    });

    res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials ' });
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
    console.log('Forgot password request body:', req.body);
    const { email } = req.body;
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

    console.log('Attempting to send email to:', user.email);

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

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
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
    const user = await User.findById(req.user.userId).select('isVerified');
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
    const user = await User.findOne({
      verificationToken: token,
      verificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully. You can now log in.' });
  } catch (error) {
    console.error('Email verification error:', error);
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
    const user = await User.findById(req.user.userId).select('plan');
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
  try {
    const user = await User.findById(req.user.userId).select('username email plan');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
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




// exports.getVCardPreview = async (req, res) => {
//   try {
//     const { vCardId } = req.params;
//     const ip = req.headers['x-forwarded-for'] || 
//                req.connection.remoteAddress || 
//                req.socket.remoteAddress ||
//                (req.connection.socket ? req.connection.socket.remoteAddress : null);

//     const user = await User.findOne({ 'vCards._id': vCardId });
//     if (!user) {
//       return res.status(404).json({ error: 'vCard not found' });
//     }

//     const vCard = user.vCards.id(vCardId);
//     if (!vCard) {
//       return res.status(404).json({ error: 'vCard not found' });
//     }

//     // Record the preview access
//     let vCardScan = await VCardScan.findOne({ vCardId });
//     if (!vCardScan) {
//       vCardScan = new VCardScan({ vCardId, scans: [] });
//     }

//     const userAgent = req.headers['user-agent'];
//     const isMobile = /Mobile|Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
//     const device = isMobile ? 'Mobile' : 'Desktop';

//     const locationData = await getLocationData(ip);

//     const scanData = {
//       ipAddress: ip,
//       userAgent,
//       scanDate: new Date(),
//       location: locationData,
//       device,
//       scanType: 'Preview'
//     };

//     vCardScan.scans.push(scanData);
//     vCardScan.previewClicks++;
//     await vCardScan.save();

//     res.json({
//       templateId: vCard.templateId,
//       fields: vCard.fields,
//       qrCodeDataUrl: vCard.qrCode
//     });
//   } catch (error) {
//     console.error('Error getting vCard preview:', error);
//     res.status(500).json({ error: 'Error getting vCard preview' });
//   }
// };



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

// exports.handleScan = async (req, res) => {
//   try {
//     const { vCardId } = req.params;
//     const userAgent = req.headers['user-agent'];

//     // Use the new combined function
//     const { ipAddress, location, fullData } = await getIpAndLocationData(req);

//     // Determine device type
//     const isMobile = /mobile/i.test(userAgent);
//     const device = isMobile ? 'Mobile' : 'Desktop';

//     // Find or create VCardScan document
//     let vCardScan = await VCardScan.findOne({ vCardId });
//     if (!vCardScan) {
//       vCardScan = new VCardScan({ vCardId, scans: [] });
//     }

//     // Create new scan entry
//     const newScan = {
//       ipAddress,
//       userAgent,
//       location,
//       device,
//       scanType: req.query.scanType || 'QR' // Default to 'QR' if not specified
//     };

//     // Add the new scan to the scans array
//     vCardScan.scans.push(newScan);

//     // Increment the appropriate counter
//     switch (newScan.scanType) {
//       case 'QR':
//         vCardScan.qrScans += 1;
//         break;
//       case 'Link':
//         vCardScan.linkClicks += 1;
//         break;
//       case 'Preview':
//         vCardScan.previewClicks += 1;
//         break;
//     }

//     await vCardScan.save();

//     res.status(200).json({ message: 'Scan recorded successfully', scanId: newScan._id });
//   } catch (error) {
//     console.error('Error handling scan:', error);
//     res.status(500).json({ error: 'Failed to record scan', details: error.message });
//   }
// };






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
