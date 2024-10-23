const express = require('express');
const router = express.Router();
const analyticsController = require('../controllers/analyticsController');
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
  getVCardAnalytics,
  getVCardPreview,
  handleScan,
  testGeolocation,
  recordTimeSpent,
  deleteVCard,
  testLocationSpecificService,
  testUserIpDetection
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

router.get('/vcard-analytics/:vCardId', authenticateJWT, analyticsController.getVCardAnalytics);

router.get('/user-analytics', authenticateJWT, getUserScanAnalytics);

router.get('/vcard-preview/:vCardId', getVCardPreview);

router.post('/scan/:vCardId', handleScan);

router.delete('/vcard/:vCardId', authenticateJWT, deleteVCard);


router.get('/test-geolocation', testGeolocation);

router.post('/scan/:vCardId/time-spent', recordTimeSpent);


router.get('/vcard-analytics/:vCardId', authenticateJWT, analyticsController.getVCardAnalytics);


router.get('/test-location-service', testLocationSpecificService);

router.get('/test-user-ip', testUserIpDetection);
module.exports = router;
