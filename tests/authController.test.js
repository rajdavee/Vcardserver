const mongoose = require('mongoose');
const User = require('../models/User');
const authController = require('../controllers/authController');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');
const { getLocationData } = require('../utils/geolocation');

jest.mock('../models/User');
jest.mock('cloudinary').v2;
jest.mock('axios');
jest.mock('../utils/geolocation');





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



   // ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  auth functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
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
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('All fields are required') });
    });
  
    it('should handle invalid email format', async () => {
      req.body = {
        username: 'testuser',
        email: 'invalid-email',
        password: 'password123',
      };
  
      await authController.register(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('Invalid email format') });
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
  
    it('should hash the password before saving the user', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };
      User.findOne.mockResolvedValue(null);
  
      const saveMock = jest.spyOn(User.prototype, 'save').mockResolvedValueOnce({
        password: 'hashedPassword123',
      });
  
      await authController.register(req, res);
  
      expect(saveMock).toHaveBeenCalled();
      expect(saveMock.mock.instances[0].password).not.toBe('password123');
    });

    it('should generate a verification token for the user', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };
      
      // Mock the `findOne` method to return null (user does not exist)
      User.findOne.mockResolvedValue(null);
    
      // Mock the User constructor to create a new user instance
      const userInstance = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'hashedPassword123', // Simulate password hashing
        verificationToken: '', // Initialize as empty
        save: jest.fn().mockResolvedValue({}),
      };
      
      User.mockImplementation(() => userInstance); // Mock the User constructor
    
      await authController.register(req, res);
    
      // Verify that a new user instance was created
      expect(userInstance.save).toHaveBeenCalled();
      
      // Check if the verificationToken was set on the user instance
      expect(userInstance.verificationToken).toEqual(expect.any(String));
    });
    
    it('should generate a valid email verification URL', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };
      User.findOne.mockResolvedValue(null);
      sendEmail.mockResolvedValue();
  
      await authController.register(req, res);
  
      expect(sendEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          text: expect.stringContaining(`${process.env.FRONTEND_URL}/verify-email?token=`),
        })
      );
    });
    it('should handle email sending failures', async () => {
      req.body = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      };
      User.findOne.mockResolvedValue(null);
      sendEmail.mockRejectedValue(new Error('Email service failed'));
  
      await authController.register(req, res);
  
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Email sending failed. Please try again later.' });
    });
it('should return error for invalid username', async () => {
  req.body = {
    username: '', // Invalid username (empty)
    email: 'test@example.com',
    password: 'password123',
  };

  await authController.register(req, res);

  // Check the response status and error message
  expect(res.status).toHaveBeenCalledWith(400);
  expect(res.json).toHaveBeenCalledWith({ error: 'Invalid username format' });
});
it('should handle weak password with missing criteria', async () => {
  req.body = {
    username: 'testuser',
    email: 'test@example.com',
    password: 'Weak1', // Missing special character
  };

  await authController.register(req, res);

  expect(res.status).toHaveBeenCalledWith(400);
  expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('Password is too weak') });
});
it('should handle potential SQL injection attempts', async () => {
  req.body = {
    username: 'testuser',
    email: 'test@example.com',
    password: 'password123; DROP TABLE users;', // SQL injection attempt
  };

  await authController.register(req, res);

  expect(res.status).toHaveBeenCalledWith(400);
  expect(res.json).toHaveBeenCalledWith({ error: 'Invalid password format' });
});
// Test for token expiration handling
it('should return error if token is expired', async () => {
  req.body = {
    username: 'testuser',
    email: 'test@example.com',
    password: 'Password123!',
  };

  // Mock the User constructor to return an object with an expired token
  User.mockImplementation(() => ({
    save: jest.fn().mockImplementation(function() {
      this.verificationExpires = Date.now() - 1000; // Token expired 1 second ago
      return Promise.resolve(this);
    }),
  }));

  await authController.register(req, res);

  expect(res.status).toHaveBeenCalledWith(400);
  expect(res.json).toHaveBeenCalledWith({ error: 'Verification token expired' });
});
it('should not allow XSS input in username', async () => {
  req.body = {
    username: '<script>alert("XSS")</script>', // Invalid username
    email: 'test@example.com',
    password: 'Password123!',
  };

  User.findOne.mockResolvedValue(null);

  // Invoke the function
  await authController.register(req, res);

  // Check that the response status is 400 and the error message is appropriate
  expect(res.status).toHaveBeenCalledWith(400);
  expect(res.json).toHaveBeenCalledWith({ error: 'Invalid username format' });
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
    it('should handle password hashing errors', async () => {
      req.body = {
        email: 'test@example.com',
        password: 'password123',
      };
      const mockUser = {
        email: 'test@example.com',
        comparePassword: jest.fn().mockRejectedValue(new Error('Hashing error')),
      };
      User.findOne.mockResolvedValue(mockUser);
    
      await authController.login(req, res);
    
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Error logging in' });
    });
    it('should return error for missing password', async () => {
      req.body = {
        email: 'test@example.com',
        // password is missing
      };
    
      await authController.login(req, res);
    
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('required') });
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
    it('should handle error when sending email', async () => {
      req.body = { email: 'test@example.com' };
      const mockUser = {
        email: 'test@example.com',
        resetPasswordToken: undefined,
        resetPasswordExpires: undefined,
        save: jest.fn().mockResolvedValue({}), // Ensure save works
      };
      User.findOne.mockResolvedValue(mockUser);
      sendEmail.mockRejectedValue(new Error('Email service error')); // Simulate email failure
    
      await authController.forgotPassword(req, res);
    
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Error sending password reset email' });
    });
    it('should return error if email is missing', async () => {
      req.body = {}; // No email provided
    
      await authController.forgotPassword(req, res);
    
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Email is required' });
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
    it('should return error for expired token', async () => {
      req.params = { token: 'validtoken' };
      req.body = { password: 'newpassword123' };
      
      // Mock user object with an expired token
      const mockUser = {
        resetPasswordToken: 'validtoken',
        resetPasswordExpires: Date.now() - 3600000, // 1 hour ago (expired)
        save: jest.fn().mockResolvedValue({}),
      };
      
      // Mock User.findOne to return the mock user
      User.findOne.mockResolvedValue(mockUser);
    
      // Call the resetPassword function
      await authController.resetPassword(req, res);
    
      // Check that the response is as expected for an expired token
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Password reset token is invalid or has expired' });
    });
    it('should return error if password is missing', async () => {
      req.params = { token: 'validtoken' };
      req.body = { password: '' }; // Empty password
      const mockUser = {
        resetPasswordToken: 'validtoken',
        resetPasswordExpires: Date.now() + 3600000,
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);
    
      await authController.resetPassword(req, res);
    
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Password is required' });
    });
    it('should return error for weak password', async () => {
      req.params = { token: 'validtoken' };
      req.body = { password: 'weak' };
      const mockUser = {
        resetPasswordToken: 'validtoken',
        resetPasswordExpires: Date.now() + 3600000,
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);
  
      await authController.resetPassword(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Password is too weak. It must be at least 8 characters long' });
    });
    it('should return error for invalid password format', async () => {
      req.params = { token: 'validtoken' };
      req.body = { password: 'invalid password!' };
      const mockUser = {
        resetPasswordToken: 'validtoken',
        resetPasswordExpires: Date.now() + 3600000,
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);
  
      await authController.resetPassword(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid password format' });
    });
    it('should reset password successfully with valid password', async () => {
      req.params = { token: 'validtoken' };
      req.body = { password: 'ValidPassword123!' };
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
    it('should handle database errors', async () => {
      req.user = { userId: 'user123' };
      User.findById.mockRejectedValue(new Error('Database error'));
    
      await authController.checkVerificationStatus(req, res);
    
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Error checking verification status' });
    });
    it('should return error if userId is missing', async () => {
      req.user = {}; // No userId
  
      await authController.checkVerificationStatus(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'User ID is required' });
    });
    it('should return error if req.user is missing', async () => {
      req.user = undefined; // req.user is missing entirely
  
      await authController.checkVerificationStatus(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'User ID is required' });
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
    it('should return error for expired verification token', async () => {
      req.params = { token: 'validtoken' };
      const mockUser = {
        verificationToken: 'validtoken',
        verificationExpires: Date.now() - 3600000, // Token is expired
        save: jest.fn().mockResolvedValue({}),
      };
      User.findOne.mockResolvedValue(mockUser);
    
      await authController.verifyEmail(req, res);
    
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Verification token has expired' });
    });
    it('should handle database errors', async () => {
      req.params = { token: 'validtoken' };
      User.findOne.mockRejectedValue(new Error('Database error'));
    
      await authController.verifyEmail(req, res);
    
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Email verification failed' });
    });
    it('should return error if token is missing', async () => {
      req.params = {}; // No token provided
    
      await authController.verifyEmail(req, res);
    
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Verification token is required' });
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
        it('should handle errors when sending verification email', async () => {
          req.body = { email: 'unverified@example.com' };
          const mockUser = {
            email: 'unverified@example.com',
            isVerified: false,
            lastVerificationSent: Date.now() - 120000, // 2 minutes ago
            save: jest.fn().mockResolvedValue({}),
          };
          User.findOne.mockResolvedValue(mockUser);
          sendEmail.mockRejectedValue(new Error('Email service error'));
        
          await authController.resendVerification(req, res);
        
          expect(res.status).toHaveBeenCalledWith(500);
          expect(res.json).toHaveBeenCalledWith({ error: 'Failed to resend verification email' });
        });

        
        

 });
 // ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  User functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
describe('getCurrentUser', () => {
  beforeEach(() => {
    req = {
      user: { userId: 'mockUserId' }
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  it('should return user data without password', async () => {
    const mockUser = {
      _id: 'mockUserId',
      username: 'testuser',
      email: 'test@example.com'
    };
    User.findById = jest.fn().mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUser)
    });

    await authController.getCurrentUser(req, res);

    expect(User.findById).toHaveBeenCalledWith('mockUserId');
    expect(res.json).toHaveBeenCalledWith(mockUser);
  });

  it('should return 404 if user is not found', async () => {
    User.findById = jest.fn().mockReturnValue({
      select: jest.fn().mockResolvedValue(null)
    });

    await authController.getCurrentUser(req, res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
  });

  it('should handle database errors', async () => {
    User.findById = jest.fn().mockReturnValue({
      select: jest.fn().mockRejectedValue(new Error('Database error'))
    });

    await authController.getCurrentUser(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Error fetching user data' });
  });
}); 
describe('getUserPlan', () => {
  beforeEach(() => {
    req = {
      user: { userId: 'mockUserId' }
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  it('should return the user plan name', async () => {
    const mockUser = {
      plan: { name: 'Premium' }
    };
    User.findById = jest.fn().mockResolvedValue(mockUser);

    await authController.getUserPlan(req, res);

    expect(User.findById).toHaveBeenCalledWith('mockUserId');
    expect(res.json).toHaveBeenCalledWith({ planName: 'Premium' });
  });

  it('should return "Free" if user has no plan', async () => {
    const mockUser = { plan: {} };
    User.findById = jest.fn().mockResolvedValue(mockUser);

    await authController.getUserPlan(req, res);

    expect(res.json).toHaveBeenCalledWith({ planName: 'Free' });
  });

  it('should return 404 if user is not found', async () => {
    User.findById = jest.fn().mockResolvedValue(null);

    await authController.getUserPlan(req, res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
  });

  it('should handle database errors', async () => {
    User.findById = jest.fn().mockRejectedValue(new Error('Database error'));

    await authController.getUserPlan(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Error fetching user plan' });
  });
});
describe('getUserInfo', () => {
  beforeEach(() => {
    req = {
      user: { userId: 'mockUserId' }
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  it('should return user info with plan details', async () => {
    const mockUser = {
      username: 'testuser',
      email: 'test@example.com',
      plan: {
        name: 'Premium',
        availableTemplates: 10,
        price: 9.99,
        subscribedAt: new Date('2023-01-01')
      }
    };
    User.findById = jest.fn().mockResolvedValue(mockUser);

    await authController.getUserInfo(req, res);

    expect(User.findById).toHaveBeenCalledWith('mockUserId');
    expect(res.json).toHaveBeenCalledWith({
      username: 'testuser',
      email: 'test@example.com',
      plan: {
        name: 'Premium',
        availableTemplates: 10,
        price: 9.99,
        subscribedAt: expect.any(Date)
      }
    });
  });

  it('should return 404 if user is not found', async () => {
    User.findById = jest.fn().mockResolvedValue(null);

    await authController.getUserInfo(req, res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
  });

  it('should handle missing plan information', async () => {
    const mockUser = {
      username: 'testuser',
      email: 'test@example.com',
      plan: {}
    };
    User.findById = jest.fn().mockResolvedValue(mockUser);

    await authController.getUserInfo(req, res);

    expect(res.json).toHaveBeenCalledWith({
      username: 'testuser',
      email: 'test@example.com',
      plan: {
        name: undefined,
        availableTemplates: undefined,
        price: undefined,
        subscribedAt: undefined
      }
    });
  });

  it('should handle database errors', async () => {
    User.findById = jest.fn().mockRejectedValue(new Error('Database error'));

    await authController.getUserInfo(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Error fetching user info' });
  });
});
 // ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{  vcard functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------



  describe('getVCardPreview', () => {
    it('should return vCard preview successfully', async () => {
      const mockVCard = {
        templateId: 'template1',
        fields: [{ name: 'name', value: 'John Doe' }],
        qrCode: 'mockQRCode'
      };
      User.findOne.mockResolvedValue({
        vCards: { id: jest.fn().mockReturnValue(mockVCard) }
      });

      req.params.vCardId = 'mockVCardId';
      await authController.getVCardPreview(req, res);

      expect(res.json).toHaveBeenCalledWith({
        templateId: 'template1',
        fields: [{ name: 'name', value: 'John Doe' }],
        qrCodeDataUrl: 'mockQRCode'
      });
    });

    it('should return 404 if vCard not found', async () => {
      User.findOne.mockResolvedValue(null);

      req.params.vCardId = 'nonExistentId';
      await authController.getVCardPreview(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'vCard not found' });
    });

    it('should handle vCard not found in user document', async () => {
      User.findOne.mockResolvedValue({
        vCards: { id: jest.fn().mockReturnValue(null) }
      });

      req.params.vCardId = 'nonExistentVCardId';
      await authController.getVCardPreview(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'vCard not found' });
    });
  });

  describe('createVCard', () => {
    it('should create a new vCard successfully', async () => {
      const mockUser = {
        _id: 'mockUserId',
        vCards: [],
        save: jest.fn().mockResolvedValue(true)
      };
      User.findById.mockResolvedValue(mockUser);
      
      const mockQRCode = {
        qrCodeDataUrl: 'mockQRCodeUrl',
        vCardString: 'mockVCardString'
      };
      jest.spyOn(authController, 'generateQRCode').mockResolvedValue(mockQRCode);
  
      req.user = { userId: 'mockUserId' };
      req.body = {
        data: JSON.stringify({
          templateId: 'template1',
          fields: [{ name: 'name', value: 'John Doe' }]
        })
      };
  
      await authController.createVCard(req, res);
  
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'vCard created successfully',
        vCardId: expect.any(String),
        qrCodeDataUrl: 'mockQRCodeUrl',
        vCardString: 'mockVCardString'
      }));
    });
  
    it('should handle file upload for profile image', async () => {
      const mockUser = {
        _id: 'mockUserId',
        vCards: [],
        save: jest.fn().mockResolvedValue(true)
      };
      User.findById.mockResolvedValue(mockUser);
      
      const mockQRCode = {
        qrCodeDataUrl: 'mockQRCodeUrl',
        vCardString: 'mockVCardString'
      };
      jest.spyOn(authController, 'generateQRCode').mockResolvedValue(mockQRCode);
  
      cloudinary.uploader.upload.mockResolvedValue({ secure_url: 'https://example.com/image.jpg' });
  
      req.user = { userId: 'mockUserId' };
      req.body = {
        data: JSON.stringify({
          templateId: 'template1',
          fields: [{ name: 'name', value: 'John Doe' }]
        })
      };
      req.files = {
        profileImage: {
          mimetype: 'image/jpeg',
          size: 1024 * 1024, // 1MB
          tempFilePath: '/tmp/mock-image.jpg'
        }
      };
  
      await authController.createVCard(req, res);
  
      expect(cloudinary.uploader.upload).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'vCard created successfully',
        vCardId: expect.any(String),
        qrCodeDataUrl: 'mockQRCodeUrl',
        vCardString: 'mockVCardString'
      }));
    });
  
    it('should handle invalid file type', async () => {
      req.user = { userId: 'mockUserId' };
      req.body = {
        data: JSON.stringify({
          templateId: 'template1',
          fields: [{ name: 'name', value: 'John Doe' }]
        })
      };
      req.files = {
        profileImage: {
          mimetype: 'application/pdf',
          size: 1024 * 1024, // 1MB
          tempFilePath: '/tmp/mock-file.pdf'
        }
      };
  
      await authController.createVCard(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid file type. Only JPEG, PNG, and GIF are allowed.'
      });
    });
  
    it('should handle file size exceeding limit', async () => {
      req.user = { userId: 'mockUserId' };
      req.body = {
        data: JSON.stringify({
          templateId: 'template1',
          fields: [{ name: 'name', value: 'John Doe' }]
        })
      };
      req.files = {
        profileImage: {
          mimetype: 'image/jpeg',
          size: 6 * 1024 * 1024, // 6MB
          tempFilePath: '/tmp/mock-image.jpg'
        }
      };
  
      await authController.createVCard(req, res);
  
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'File size exceeds the 5MB limit.'
      });
    });
  });
  
  describe('getPublicVCardPreview', () => {
    it('should return public vCard preview successfully', async () => {
      const mockVCard = {
        templateId: 'template1',
        fields: [{ name: 'name', value: 'John Doe' }]
      };
      User.findOne.mockResolvedValue({
        vCards: { id: jest.fn().mockReturnValue(mockVCard) }
      });

      req.params.vCardId = 'mockVCardId';
      await authController.getPublicVCardPreview(req, res);

      expect(res.json).toHaveBeenCalledWith({
        templateId: 'template1',
        fields: [{ name: 'name', value: 'John Doe' }]
      });
    });

    it('should return 404 if public vCard not found', async () => {
      User.findOne.mockResolvedValue(null);

      req.params.vCardId = 'nonExistentId';
      await authController.getPublicVCardPreview(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'vCard not found' });
    });
  });

  describe('getVCard', () => {
    it('should return vCard successfully', async () => {
      const mockVCard = {
        _id: 'mockVCardId',
        templateId: 'template1',
        fields: [{ name: 'name', value: 'John Doe' }],
        qrCode: 'mockQRCode'
      };
      User.findOne.mockResolvedValue({
        vCards: { id: jest.fn().mockReturnValue(mockVCard) }
      });

      req.params.userId = 'mockUserId';
      req.params.vCardId = 'mockVCardId';
      await authController.getVCard(req, res);

      expect(res.json).toHaveBeenCalledWith({
        ...mockVCard,
        qrCodeDataUrl: 'mockQRCode'
      });
    });

    it('should return 404 if vCard not found', async () => {
      User.findOne.mockResolvedValue(null);

      req.params.userId = 'mockUserId';
      req.params.vCardId = 'nonExistentId';
      await authController.getVCard(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'vCard not found' });
    });
  });

  describe('getPublicVCard', () => {
    it('should return public vCard successfully', async () => {
      const mockVCard = {
        _id: 'mockVCardId',
        templateId: 'template1',
        fields: [{ name: 'name', value: 'John Doe' }],
        qrCode: 'mockQRCode'
      };
      User.findOne.mockResolvedValue({
        vCards: { id: jest.fn().mockReturnValue(mockVCard) }
      });

      req.params.id = 'mockVCardId';
      await authController.getPublicVCard(req, res);

      expect(res.json).toHaveBeenCalledWith({
        ...mockVCard.toObject(),
        qrCodeDataUrl: 'mockQRCode'
      });
    });

    it('should return 404 if public vCard not found', async () => {
      User.findOne.mockResolvedValue(null);

      req.params.id = 'nonExistentId';
      await authController.getPublicVCard(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'vCard not found' });
    });
  });

  describe('handleScan', () => {
    it('should record scan successfully', async () => {
      const mockVCard = {
        _id: 'mockVCardId',
        scans: []
      };
      const mockUser = {
        vCards: { id: jest.fn().mockReturnValue(mockVCard) },
        save: jest.fn().mockResolvedValue(true)
      };
      User.findOne.mockResolvedValue(mockUser);
      
      getLocationData.mockResolvedValue({
        city: 'Test City',
        region: 'Test Region',
        country_name: 'Test Country',
        latitude: 0,
        longitude: 0
      });

      req.params.id = 'mockVCardId';
      req.headers['x-forwarded-for'] = '127.0.0.1';
      await authController.handleScan(req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Scan recorded successfully'
      }));
    });

    it('should handle vCard not found', async () => {
      User.findOne.mockResolvedValue(null);

      req.params.id = 'nonExistentId';
      await authController.handleScan(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'vCard not found' });
    });
  });

  describe('getVCards', () => {
    it('should return all vCards for a user', async () => {
      const mockUser = {
        vCards: [
          { _id: 'vcard1', templateId: 'template1' },
          { _id: 'vcard2', templateId: 'template2' }
        ]
      };
      User.findById.mockResolvedValue(mockUser);

      req.user = { userId: 'mockUserId' };
      await authController.getVCards(req, res);

      expect(res.json).toHaveBeenCalledWith({
        vCards: mockUser.vCards,
        count: 2
      });
    });

    it('should return empty array if user has no vCards', async () => {
      const mockUser = { vCards: [] };
      User.findById.mockResolvedValue(mockUser);

      req.user = { userId: 'mockUserId' };
      await authController.getVCards(req, res);

      expect(res.json).toHaveBeenCalledWith({
        vCards: [],
        count: 0
      });
    });

    it('should return 404 if user not found', async () => {
      User.findById.mockResolvedValue(null);

      req.user = { userId: 'nonExistentId' };
      await authController.getVCards(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ error: 'User not found' });
    });
  });

  describe('testGeolocation', () => {
    it('should return geolocation data successfully', async () => {
      const mockLocationData = {
        city: 'Test City',
        region: 'Test Region',
        country_name: 'Test Country',
        latitude: 0,
        longitude: 0
      };
      getLocationData.mockResolvedValue(mockLocationData);

      req.query.ip = '8.8.8.8';
      await authController.testGeolocation(req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        location: expect.objectContaining(mockLocationData)
      }));
    });

    it('should handle geolocation service error', async () => {
      getLocationData.mockRejectedValue(new Error('Geolocation service error'));

      req.query.ip = '8.8.8.8';
      await authController.testGeolocation(req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ 
        success: false, 
        error: 'Error detecting user IP or fetching location data' 
      });
    });
  });

  describe('testLocationSpecificService', () => {
    it('should return location data successfully', async () => {
      const mockLocationData = {
        region: 'Test Region',
        country_name: 'Test Country'
      };
      axios.get.mockResolvedValue({ data: mockLocationData });

      req.headers['x-forwarded-for'] = '8.8.8.8';
      await authController.testLocationSpecificService(req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        message: `You are from Test Region, Test Country`,
        data: mockLocationData
      }));
    });

    it('should handle location service error', async () => {
      axios.get.mockRejectedValue(new Error('Location service error'));

      req.headers['x-forwarded-for'] = '8.8.8.8';
      await authController.testLocationSpecificService(req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ 
        success: false, 
        error: 'Error fetching location data' 
      });
    });
  });





});







