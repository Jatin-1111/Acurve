// src/routes/auth.routes.ts
import { Router } from "express";
import { authController } from "../controllers/auth.controller.ts";
import {
  authenticate,
  auditLog,
  securityHeaders,
} from "../middleware/auth.middleware.ts";
import rateLimit from "express-rate-limit";

const router = Router();

// ============================================================================
// RATE LIMITING CONFIGURATION
// ============================================================================

// Strict rate limiting for auth endpoints
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    success: false,
    error: "Too many authentication attempts, please try again later",
    code: "RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Moderate rate limiting for other endpoints
const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: {
    success: false,
    error: "Too many requests, please try again later",
    code: "RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============================================================================
// PUBLIC ROUTES (No authentication required)
// ============================================================================

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user
 * @access  Public
 * @body    { email, password, firstName, lastName, role }
 */
router.post(
  "/register",
  securityHeaders,
  authRateLimit,
  auditLog("USER_REGISTER"),
  authController.register.bind(authController)
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login user
 * @access  Public
 * @body    { email, password }
 */
router.post(
  "/login",
  securityHeaders,
  authRateLimit,
  auditLog("USER_LOGIN"),
  authController.login.bind(authController)
);

/**
 * @route   POST /api/v1/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 * @body    { refreshToken }
 */
router.post(
  "/refresh",
  securityHeaders,
  generalRateLimit,
  auditLog("TOKEN_REFRESH"),
  authController.refreshTokens.bind(authController)
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 * @body    { email }
 */
router.post(
  "/forgot-password",
  securityHeaders,
  authRateLimit,
  auditLog("PASSWORD_RESET_REQUEST"),
  authController.forgotPassword.bind(authController)
);

/**
 * @route   POST /api/v1/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 * @body    { token, newPassword }
 */
router.post(
  "/reset-password",
  securityHeaders,
  authRateLimit,
  auditLog("PASSWORD_RESET"),
  authController.resetPassword.bind(authController)
);

/**
 * @route   GET /api/v1/auth/verify-email/:token
 * @desc    Verify email address
 * @access  Public
 */
router.get(
  "/verify-email/:token",
  securityHeaders,
  generalRateLimit,
  auditLog("EMAIL_VERIFICATION"),
  authController.verifyEmail.bind(authController)
);

/**
 * @route   GET /api/v1/auth/check-email
 * @desc    Check if email is available
 * @access  Public
 * @query   email
 */
router.get(
  "/check-email",
  securityHeaders,
  generalRateLimit,
  authController.checkEmailAvailability.bind(authController)
);

// ============================================================================
// PROTECTED ROUTES (Authentication required)
// ============================================================================

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user (invalidate refresh token)
 * @access  Private
 * @body    { refreshToken }
 */
router.post(
  "/logout",
  securityHeaders,
  generalRateLimit,
  auditLog("USER_LOGOUT"),
  authController.logout.bind(authController)
);

/**
 * @route   POST /api/v1/auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.post(
  "/logout-all",
  securityHeaders,
  authenticate,
  generalRateLimit,
  auditLog("USER_LOGOUT_ALL"),
  authController.logoutAll.bind(authController)
);

/**
 * @route   GET /api/v1/auth/profile
 * @desc    Get current user profile
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.get(
  "/profile",
  securityHeaders,
  authenticate,
  generalRateLimit,
  authController.getProfile.bind(authController)
);

/**
 * @route   PUT /api/v1/auth/profile
 * @desc    Update user profile
 * @access  Private
 * @headers Authorization: Bearer <token>
 * @body    { firstName?, lastName?, phone?, etc. }
 */
router.put(
  "/profile",
  securityHeaders,
  authenticate,
  generalRateLimit,
  auditLog("PROFILE_UPDATE"),
  authController.updateProfile.bind(authController)
);

/**
 * @route   PUT /api/v1/auth/change-password
 * @desc    Change user password
 * @access  Private
 * @headers Authorization: Bearer <token>
 * @body    { currentPassword, newPassword }
 */
router.put(
  "/change-password",
  securityHeaders,
  authenticate,
  authRateLimit,
  auditLog("PASSWORD_CHANGE"),
  authController.changePassword.bind(authController)
);

/**
 * @route   GET /api/v1/auth/sessions
 * @desc    Get user's active sessions
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.get(
  "/sessions",
  securityHeaders,
  authenticate,
  generalRateLimit,
  authController.getSessions.bind(authController)
);

/**
 * @route   DELETE /api/v1/auth/sessions/:sessionId
 * @desc    Revoke a specific session
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.delete(
  "/sessions/:sessionId",
  securityHeaders,
  authenticate,
  generalRateLimit,
  auditLog("SESSION_REVOKE"),
  authController.revokeSession.bind(authController)
);

/**
 * @route   POST /api/v1/auth/resend-verification
 * @desc    Resend email verification
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.post(
  "/resend-verification",
  securityHeaders,
  authenticate,
  authRateLimit,
  auditLog("RESEND_EMAIL_VERIFICATION"),
  authController.resendEmailVerification.bind(authController)
);

/**
 * @route   POST /api/v1/auth/upload-profile-image
 * @desc    Upload profile image
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.post(
  "/upload-profile-image",
  securityHeaders,
  authenticate,
  generalRateLimit,
  auditLog("PROFILE_IMAGE_UPLOAD"),
  authController.uploadProfileImage.bind(authController)
);

// ============================================================================
// ADMIN ONLY ROUTES
// ============================================================================

/**
 * @route   GET /api/v1/auth/stats
 * @desc    Get user statistics (Admin only)
 * @access  Private (Admin)
 * @headers Authorization: Bearer <token>
 */
router.get(
  "/stats",
  securityHeaders,
  authenticate,
  generalRateLimit,
  authController.getUserStats.bind(authController)
);

/**
 * @route   POST /api/v1/auth/cleanup-sessions
 * @desc    Cleanup expired sessions (Admin only)
 * @access  Private (Admin)
 * @headers Authorization: Bearer <token>
 */
router.post(
  "/cleanup-sessions",
  securityHeaders,
  authenticate,
  generalRateLimit,
  auditLog("CLEANUP_SESSIONS"),
  authController.cleanupSessions.bind(authController)
);

// ============================================================================
// HEALTH CHECK ROUTE
// ============================================================================

/**
 * @route   GET /api/v1/auth/health
 * @desc    Auth service health check
 * @access  Public
 */
router.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "Auth service is healthy",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    endpoints: {
      public: [
        "POST /register",
        "POST /login",
        "POST /refresh",
        "POST /forgot-password",
        "POST /reset-password",
        "GET /verify-email/:token",
        "GET /check-email",
      ],
      protected: [
        "GET /profile",
        "PUT /profile",
        "PUT /change-password",
        "POST /logout",
        "POST /logout-all",
        "GET /sessions",
        "DELETE /sessions/:sessionId",
        "POST /resend-verification",
        "POST /upload-profile-image",
      ],
      admin: ["GET /stats", "POST /cleanup-sessions"],
    },
  });
});

export default router;
