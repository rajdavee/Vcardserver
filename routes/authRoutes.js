const express = require('express');
const router = express.Router();
const { 
  register, 
  login, 
  forgotPassword, 
  resetPassword, 
  getCurrentUser, 
  getUserPlan, 
  getUserInfo, 
  createVCard, 
  updateVCard, 
  getVCards,
  getVCard,
  getPublicVCard,
  uploadChunk,
  getPublicVCardPreview,
  verifyEmail,
  resendVerification,
  checkVerificationStatus,
  handleQRScan,
  getVCardScanAnalytics,
  getUserScanAnalytics,
  getVCardAnalytics
} = require('../controllers/authController');
const authenticateJWT = require('../middleware/authMiddleware');

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);
router.get('/getUser', authenticateJWT, getCurrentUser);
router.get('/user-info', authenticateJWT, getUserInfo);
router.get('/user-plan', authenticateJWT, getUserPlan);
router.post('/vcard', authenticateJWT, createVCard);
router.put('/vcard/:vCardId', authenticateJWT, updateVCard);
router.get('/vcard/:vCardId', authenticateJWT, getVCard);
router.get('/vcards', authenticateJWT, getVCards);
router.get('/public-vcard/:vCardId', getPublicVCard);
router.get('/public-vcard-preview/:vCardId', getPublicVCardPreview); 
router.post('/upload-chunk', authenticateJWT, uploadChunk);

router.get('/verify-email/:token', verifyEmail);
router.post('/resend-verification', resendVerification);

router.get('/verification-status', authenticateJWT, checkVerificationStatus);
router.get('/scan/:vCardId', handleQRScan);

router.get('/vcard-analytics/:vCardId', authenticateJWT, getVCardAnalytics);

router.get('/user-analytics', authenticateJWT, getUserScanAnalytics);

module.exports = router;