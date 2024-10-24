const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authController = require('../controllers/authController');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');

// Mock dependencies
jest.mock('../models/User');
jest.mock('../utils/sendEmail');
jest.mock('jsonwebtoken');

describe('Auth Controller', () => {
  let req, res, next;

  beforeEach(() => {
    req = {
      body: {},
      params: {},
      user: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };
      User.findOne.mockResolvedValue(null);
      User.prototype.save.mockResolvedValue({});
      sendEmail.mockResolvedValue();

      await authController.register(req, res);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: expect.stringContaining('User registered successfully'),
      }));
    });

    it('should return error if user already exists', async () => {
      req.body = {
        username: 'existinguser',
        email: 'existing@example.com',
        password: 'password123',
      };
      User.findOne.mockResolvedValue({ email: 'existing@example.com' });

      await authController.register(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'User already exists' });
    });

    it('should handle missing required fields', async () => {
      req.body = {
        username: 'testuser',
        // email is missing
        password: 'password123',
      };

      await authController.register(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('required') });
    });

    it('should handle invalid email format', async () => {
      req.body = {
        username: 'testuser',
        email: 'invalid-email',
        password: 'password123',
      };

      await authController.register(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('valid email') });
    });

    it('should handle weak password', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'weak',
      };

      await authController.register(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('Password is too weak') });
    });

    it('should handle database errors', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };
      User.findOne.mockRejectedValue(new Error('Database error'));

      await authController.register(req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Registration failed. Please try again later.' });
    });
  });

  describe('login', () => {
    it('should login user successfully', async () => {
      req.body = {
        email: 'test@example.com',
        password: 'password123',
      };
      const mockUser = {
        _id: 'user123',
        email: 'test@example.com',
        password: await bcrypt.hash('password123', 10),
        isVerified: true,
        comparePassword: jest.fn().mockResolvedValue(true),
      };
      User.findOne.mockResolvedValue(mockUser);
      jwt.sign.mockReturnValue('mockedtoken');

      await authController.login(req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        token: 'mockedtoken',
        user: expect.objectContaining({ email: 'test@example.com' }),
      }));
    });

    it('should return error for invalid credentials', async () => {
      req.body = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };
      const mockUser = {
        email: 'test@example.com',
        comparePassword: jest.fn().mockResolvedValue(false),
      };
      User.findOne.mockResolvedValue(mockUser);

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid credentials' });
    });

    it('should return error for unverified email', async () => {
      req.body = {
        email: 'unverified@example.com',
        password: 'password123',
      };
      const mockUser = {
        email: 'unverified@example.com',
        isVerified: false,
        comparePassword: jest.fn().mockResolvedValue(true),
      };
      User.findOne.mockResolvedValue(mockUser);

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Please verify your email before logging in' });
    });

    it('should handle non-existent user', async () => {
      req.body = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };
      User.findOne.mockResolvedValue(null);

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid credentials' });
    });

    it('should handle missing email or password', async () => {
      req.body = {
        // email is missing
        password: 'password123',
      };

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('required') });
    });

    it('should handle database errors during login', async () => {
      req.body = {
        email: 'test@example.com',
        password: 'password123',
      };
      User.findOne.mockRejectedValue(new Error('Database error'));

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Error logging in' });
    });
  });

  describe('forgotPassword', () => {
    it('should send reset password email successfully', async () => {
      req.body = { email: 'test@example.com' };
      const mockUser = {
        email: 'test@example.com',
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);
      sendEmail.mockResolvedValue();

      await authController.forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: 'Password reset email sent' });
    });

    it('should return error if user not found', async () => {
      req.body = { email: 'nonexistent@example.com' };
      User.findOne.mockResolvedValue(null);

      await authController.forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
    });
  });

  describe('resetPassword', () => {
    it('should reset password successfully', async () => {
      req.params = { token: 'validtoken' };
      req.body = { password: 'newpassword123' };
      const mockUser = {
        resetPasswordToken: 'validtoken',
        resetPasswordExpires: Date.now() + 3600000,
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);

      await authController.resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: 'Password has been reset' });
    });

    it('should return error for invalid or expired token', async () => {
      req.params = { token: 'invalidtoken' };
      req.body = { password: 'newpassword123' };
      User.findOne.mockResolvedValue(null);

      await authController.resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Password reset token is invalid or has expired' });
    });
  });

  describe('checkVerificationStatus', () => {
    it('should return verification status successfully', async () => {
      req.user = { userId: 'user123' };
      const mockUser = { isVerified: true };
      User.findById.mockResolvedValue(mockUser);

      await authController.checkVerificationStatus(req, res);

      expect(res.json).toHaveBeenCalledWith({ isVerified: true });
    });

    it('should return error if user not found', async () => {
      req.user = { userId: 'nonexistent' };
      User.findById.mockResolvedValue(null);

      await authController.checkVerificationStatus(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
    });
  });

  describe('verifyEmail', () => {
    it('should verify email successfully', async () => {
      req.params = { token: 'validtoken' };
      const mockUser = {
        verificationToken: 'validtoken',
        verificationExpires: Date.now() + 3600000,
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);

      await authController.verifyEmail(req, res);

      expect(res.json).toHaveBeenCalledWith({ message: 'Email verified successfully. You can now log in.' });
    });

    it('should return error for invalid or expired token', async () => {
      req.params = { token: 'invalidtoken' };
      User.findOne.mockResolvedValue(null);

      await authController.verifyEmail(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid or expired verification token' });
    });
  });

  describe('resendVerification', () => {
    it('should resend verification email successfully', async () => {
      req.body = { email: 'unverified@example.com' };
      const mockUser = {
        email: 'unverified@example.com',
        isVerified: false,
        lastVerificationSent: Date.now() - 120000, // 2 minutes ago
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);
      sendEmail.mockResolvedValue();

      await authController.resendVerification(req, res);

      expect(res.json).toHaveBeenCalledWith({ message: 'Verification email sent. Please check your inbox.' });
    });

    it('should return error if user not found', async () => {
      req.body = { email: 'nonexistent@example.com' };
      User.findOne.mockResolvedValue(null);

      await authController.resendVerification(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
    });

    it('should return error if email already verified', async () => {
      req.body = { email: 'verified@example.com' };
      const mockUser = {
        email: 'verified@example.com',
        isVerified: true,
      };
      User.findOne.mockResolvedValue(mockUser);

      await authController.resendVerification(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Email already verified' });
    });

    it('should return error if verification email sent too recently', async () => {
      req.body = { email: 'recent@example.com' };
      const mockUser = {
        email: 'recent@example.com',
        isVerified: false,
        lastVerificationSent: Date.now() - 30000, // 30 seconds ago
      };
      User.findOne.mockResolvedValue(mockUser);

      await authController.resendVerification(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Please wait a minute before requesting a new verification email' });
    });
  });
});
