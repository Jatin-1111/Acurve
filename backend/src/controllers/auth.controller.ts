// src/controllers/auth.controller.ts
import { Request, Response } from "express";
import {
  authService,
  registerSchema,
  loginSchema,
  refreshTokenSchema,
} from "../services/auth.service.ts";
import { UserRole } from "../generated/prisma/index.ts";

// ============================================================================
// AUTH CONTROLLER CLASS
// ============================================================================

export class AuthController {
  // ========================================================================
  // REGISTER NEW USER
  // ========================================================================

  async register(req: Request, res: Response): Promise<void> {
    try {
      const result = await authService.register(req.body);

      // Log successful registration
      console.log(
        `✅ User registered: ${result.user.email} (${result.user.role})`
      );

      res.status(201).json({
        success: true,
        message: "User registered successfully",
        data: {
          user: result.user,
          tokens: result.tokens,
        },
      });
    } catch (error: any) {
      console.error("❌ Registration failed:", error.message);

      // Handle validation errors
      if (error.name === "ZodError") {
        res.status(400).json({
          success: false,
          error: "Validation failed",
          details: error.errors,
          code: "VALIDATION_ERROR",
        });
        return;
      }

      // Handle duplicate user error
      if (error.message.includes("already exists")) {
        res.status(409).json({
          success: false,
          error: error.message,
          code: "USER_EXISTS",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Registration failed",
        code: "REGISTRATION_ERROR",
      });
    }
  }

  // ========================================================================
  // LOGIN USER
  // ========================================================================

  async login(req: Request, res: Response): Promise<void> {
    try {
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        timestamp: new Date(),
      };

      const result = await authService.login(req.body, deviceInfo);

      // Log successful login
      console.log(
        `✅ User logged in: ${result.user.email} (${result.user.role})`
      );

      res.json({
        success: true,
        message: "Login successful",
        data: {
          user: result.user,
          tokens: result.tokens,
        },
      });
    } catch (error: any) {
      console.error("❌ Login failed:", error.message);

      // Handle validation errors
      if (error.name === "ZodError") {
        res.status(400).json({
          success: false,
          error: "Validation failed",
          details: error.errors,
          code: "VALIDATION_ERROR",
        });
        return;
      }

      // Handle auth-specific errors
      if (error.message.includes("Invalid credentials")) {
        res.status(401).json({
          success: false,
          error: "Invalid email or password",
          code: "INVALID_CREDENTIALS",
        });
        return;
      }

      if (error.message.includes("Account locked")) {
        res.status(423).json({
          success: false,
          error: error.message,
          code: "ACCOUNT_LOCKED",
        });
        return;
      }

      if (error.message.includes("not active")) {
        res.status(403).json({
          success: false,
          error: "Account is not active",
          code: "ACCOUNT_INACTIVE",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Login failed",
        code: "LOGIN_ERROR",
      });
    }
  }

  // ========================================================================
  // REFRESH TOKENS
  // ========================================================================

  async refreshTokens(req: Request, res: Response): Promise<void> {
    try {
      const tokens = await authService.refreshTokens(req.body);

      res.json({
        success: true,
        message: "Tokens refreshed successfully",
        data: { tokens },
      });
    } catch (error: any) {
      console.error("❌ Token refresh failed:", error.message);

      if (error.name === "ZodError") {
        res.status(400).json({
          success: false,
          error: "Validation failed",
          details: error.errors,
          code: "VALIDATION_ERROR",
        });
        return;
      }

      res.status(401).json({
        success: false,
        error: "Invalid refresh token",
        code: "INVALID_REFRESH_TOKEN",
      });
    }
  }

  // ========================================================================
  // LOGOUT
  // ========================================================================

  async logout(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          error: "Refresh token required",
          code: "MISSING_REFRESH_TOKEN",
        });
        return;
      }

      await authService.logout(refreshToken);

      res.json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error: any) {
      console.error("❌ Logout failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Logout failed",
        code: "LOGOUT_ERROR",
      });
    }
  }

  // ========================================================================
  // LOGOUT FROM ALL DEVICES
  // ========================================================================

  async logoutAll(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      await authService.logoutAll(req.user.id);

      res.json({
        success: true,
        message: "Logged out from all devices successfully",
      });
    } catch (error: any) {
      console.error("❌ Logout all failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Logout failed",
        code: "LOGOUT_ALL_ERROR",
      });
    }
  }

  // ========================================================================
  // GET CURRENT USER PROFILE
  // ========================================================================

  async getProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      res.json({
        success: true,
        data: { user: req.user },
      });
    } catch (error: any) {
      console.error("❌ Get profile failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Get profile failed",
        code: "PROFILE_ERROR",
      });
    }
  }

  // ========================================================================
  // CHANGE PASSWORD
  // ========================================================================

  async changePassword(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        res.status(400).json({
          success: false,
          error: "Current password and new password are required",
          code: "MISSING_PASSWORDS",
        });
        return;
      }

      await authService.changePassword(
        req.user.id,
        currentPassword,
        newPassword
      );

      res.json({
        success: true,
        message: "Password changed successfully",
      });
    } catch (error: any) {
      console.error("❌ Change password failed:", error.message);

      if (error.message.includes("Current password is incorrect")) {
        res.status(400).json({
          success: false,
          error: "Current password is incorrect",
          code: "INCORRECT_CURRENT_PASSWORD",
        });
        return;
      }

      if (error.name === "ZodError") {
        res.status(400).json({
          success: false,
          error: "New password does not meet requirements",
          details: error.errors,
          code: "INVALID_NEW_PASSWORD",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Password change failed",
        code: "PASSWORD_CHANGE_ERROR",
      });
    }
  }

  // ========================================================================
  // GET ACTIVE SESSIONS
  // ========================================================================

  async getSessions(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      const sessions = await authService.getActiveSessions(req.user.id);

      res.json({
        success: true,
        data: { sessions },
      });
    } catch (error: any) {
      console.error("❌ Get sessions failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Failed to get sessions",
        code: "GET_SESSIONS_ERROR",
      });
    }
  }

  // ========================================================================
  // REVOKE SESSION
  // ========================================================================

  async revokeSession(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      const { sessionId } = req.params;

      if (!sessionId) {
        res.status(400).json({
          success: false,
          error: "Session ID is required",
          code: "MISSING_SESSION_ID",
        });
        return;
      }

      await authService.revokeSession(req.user.id, sessionId);

      res.json({
        success: true,
        message: "Session revoked successfully",
      });
    } catch (error: any) {
      console.error("❌ Revoke session failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Failed to revoke session",
        code: "REVOKE_SESSION_ERROR",
      });
    }
  }

  // ========================================================================
  // UPDATE PROFILE
  // ========================================================================

  async updateProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      const allowedFields = [
        "firstName",
        "lastName",
        "displayName",
        "phone",
        "alternatePhone",
        "dateOfBirth",
        "gender",
        "bio",
        "address",
      ];

      const updateData: any = {};

      // Filter only allowed fields
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      }

      if (Object.keys(updateData).length === 0) {
        res.status(400).json({
          success: false,
          error: "No valid fields provided for update",
          code: "NO_UPDATE_DATA",
          allowedFields,
        });
        return;
      }

      const updatedProfile = await authService.updateProfile(
        req.user.id,
        updateData
      );

      res.json({
        success: true,
        message: "Profile updated successfully",
        data: { profile: updatedProfile },
      });
    } catch (error: any) {
      console.error("❌ Update profile failed:", error.message);

      if (error.name === "ZodError") {
        res.status(400).json({
          success: false,
          error: "Validation failed",
          details: error.errors,
          code: "VALIDATION_ERROR",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Profile update failed",
        code: "PROFILE_UPDATE_ERROR",
      });
    }
  }

  // ========================================================================
  // UPLOAD PROFILE IMAGE
  // ========================================================================

  async uploadProfileImage(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      // TODO: Implement file upload logic
      // This would handle image upload to cloud storage (AWS S3, Cloudinary, etc.)

      res.json({
        success: true,
        message: "Profile image upload feature coming soon",
        code: "FEATURE_NOT_IMPLEMENTED",
      });
    } catch (error: any) {
      console.error("❌ Upload profile image failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Profile image upload failed",
        code: "IMAGE_UPLOAD_ERROR",
      });
    }
  }

  // ========================================================================
  // VERIFY EMAIL
  // ========================================================================

  async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.params;

      if (!token) {
        res.status(400).json({
          success: false,
          error: "Verification token is required",
          code: "MISSING_TOKEN",
        });
        return;
      }

      const result = await authService.verifyEmail(token);

      res.json({
        success: true,
        message: "Email verified successfully",
        data: { user: result },
      });
    } catch (error: any) {
      console.error("❌ Email verification failed:", error.message);

      if (
        error.message.includes("Invalid") ||
        error.message.includes("expired")
      ) {
        res.status(400).json({
          success: false,
          error: "Invalid or expired verification token",
          code: "INVALID_TOKEN",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Email verification failed",
        code: "EMAIL_VERIFICATION_ERROR",
      });
    }
  }

  // ========================================================================
  // RESEND EMAIL VERIFICATION
  // ========================================================================

  async resendEmailVerification(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      await authService.resendEmailVerification(req.user.id);

      res.json({
        success: true,
        message: "Verification email sent successfully",
      });
    } catch (error: any) {
      console.error("❌ Resend verification failed:", error.message);

      if (error.message.includes("already verified")) {
        res.status(400).json({
          success: false,
          error: "Email is already verified",
          code: "ALREADY_VERIFIED",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Failed to send verification email",
        code: "RESEND_VERIFICATION_ERROR",
      });
    }
  }

  // ========================================================================
  // FORGOT PASSWORD
  // ========================================================================

  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      if (!email) {
        res.status(400).json({
          success: false,
          error: "Email is required",
          code: "MISSING_EMAIL",
        });
        return;
      }

      await authService.forgotPassword(email);

      // Always return success for security (don't reveal if email exists)
      res.json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent",
      });
    } catch (error: any) {
      console.error("❌ Forgot password failed:", error.message);

      // Always return the same message for security
      res.json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent",
      });
    }
  }

  // ========================================================================
  // RESET PASSWORD
  // ========================================================================

  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        res.status(400).json({
          success: false,
          error: "Reset token and new password are required",
          code: "MISSING_REQUIRED_FIELDS",
        });
        return;
      }

      await authService.resetPassword(token, newPassword);

      res.json({
        success: true,
        message: "Password reset successfully",
      });
    } catch (error: any) {
      console.error("❌ Password reset failed:", error.message);

      if (
        error.message.includes("Invalid") ||
        error.message.includes("expired")
      ) {
        res.status(400).json({
          success: false,
          error: "Invalid or expired reset token",
          code: "INVALID_RESET_TOKEN",
        });
        return;
      }

      if (error.name === "ZodError") {
        res.status(400).json({
          success: false,
          error: "New password does not meet requirements",
          details: error.errors,
          code: "INVALID_PASSWORD",
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: "Password reset failed",
        code: "PASSWORD_RESET_ERROR",
      });
    }
  }

  // ========================================================================
  // CHECK EMAIL AVAILABILITY
  // ========================================================================

  async checkEmailAvailability(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.query;

      if (!email || typeof email !== "string") {
        res.status(400).json({
          success: false,
          error: "Email parameter is required",
          code: "MISSING_EMAIL",
        });
        return;
      }

      const isAvailable = await authService.checkEmailAvailability(email);

      res.json({
        success: true,
        data: {
          email,
          available: isAvailable,
        },
      });
    } catch (error: any) {
      console.error("❌ Check email availability failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Failed to check email availability",
        code: "EMAIL_CHECK_ERROR",
      });
    }
  }

  // ========================================================================
  // GET USER STATISTICS (Admin only)
  // ========================================================================

  async getUserStats(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      // Check if user has admin privileges
      if (!["ADMIN", "SUPER_ADMIN"].includes(req.user.role)) {
        res.status(403).json({
          success: false,
          error: "Admin privileges required",
          code: "INSUFFICIENT_PERMISSIONS",
        });
        return;
      }

      const stats = await authService.getUserStats();

      res.json({
        success: true,
        data: { stats },
      });
    } catch (error: any) {
      console.error("❌ Get user stats failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Failed to get user statistics",
        code: "USER_STATS_ERROR",
      });
    }
  }

  // ========================================================================
  // CLEANUP EXPIRED SESSIONS (Admin only)
  // ========================================================================

  async cleanupSessions(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: "Authentication required",
          code: "NOT_AUTHENTICATED",
        });
        return;
      }

      // Check if user has admin privileges
      if (!["ADMIN", "SUPER_ADMIN"].includes(req.user.role)) {
        res.status(403).json({
          success: false,
          error: "Admin privileges required",
          code: "INSUFFICIENT_PERMISSIONS",
        });
        return;
      }

      await authService.cleanupExpiredSessions();

      res.json({
        success: true,
        message: "Expired sessions cleaned up successfully",
      });
    } catch (error: any) {
      console.error("❌ Cleanup sessions failed:", error.message);

      res.status(500).json({
        success: false,
        error: "Failed to cleanup sessions",
        code: "CLEANUP_SESSIONS_ERROR",
      });
    }
  }
}

export const authController = new AuthController();
