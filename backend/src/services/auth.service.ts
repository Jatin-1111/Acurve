// src/services/auth.service.ts
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  PrismaClient,
  UserRole,
  UserStatus,
} from "../generated/prisma/index.js";
import { z } from "zod";

const prisma = new PrismaClient();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

export const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      "Password must contain uppercase, lowercase, number, and special character"
    ),
  firstName: z.string().min(2, "First name must be at least 2 characters"),
  lastName: z.string().min(2, "Last name must be at least 2 characters"),
  role: z.nativeEnum(UserRole),
  // Optional fields
  phone: z.string().optional(),
  dateOfBirth: z.string().datetime().optional(),
});

export const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(1, "Password is required"),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token is required"),
});

// ============================================================================
// TYPES
// ============================================================================

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthUser {
  id: string;
  email: string;
  role: UserRole;
  status: UserStatus;
  profile: {
    firstName: string;
    lastName: string;
    displayName: string | null;
  } | null;
}

export interface LoginResponse {
  user: AuthUser;
  tokens: AuthTokens;
}

// ============================================================================
// AUTH SERVICE CLASS
// ============================================================================

export class AuthService {
  private readonly JWT_SECRET = process.env.JWT_SECRET!;
  private readonly JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;
  private readonly ACCESS_TOKEN_EXPIRES = "15m"; // Short-lived access tokens
  private readonly REFRESH_TOKEN_EXPIRES = "7d"; // Long-lived refresh tokens
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes

  // ========================================================================
  // REGISTRATION
  // ========================================================================

  async register(data: z.infer<typeof registerSchema>): Promise<LoginResponse> {
    // Validate input
    const validatedData = registerSchema.parse(data);

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: validatedData.email.toLowerCase() },
    });

    if (existingUser) {
      throw new Error("User with this email already exists");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(
      validatedData.password,
      parseInt(process.env.BCRYPT_ROUNDS || "12")
    );

    // Create user with profile in a transaction
    const user = await prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          email: validatedData.email.toLowerCase(),
          password: hashedPassword,
          role: validatedData.role,
          status: UserStatus.ACTIVE,
          profile: {
            create: {
              firstName: validatedData.firstName,
              lastName: validatedData.lastName,
              displayName: `${validatedData.firstName} ${validatedData.lastName}`,
              phone: validatedData.phone,
              dateOfBirth: validatedData.dateOfBirth
                ? new Date(validatedData.dateOfBirth)
                : null,
            },
          },
        },
        include: {
          profile: true,
        },
      });

      return newUser;
    });

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.role);

    // Create session
    await this.createSession(user.id, tokens.refreshToken);

    return {
      user: this.sanitizeUser(user),
      tokens,
    };
  }

  // ========================================================================
  // LOGIN
  // ========================================================================

  async login(
    data: z.infer<typeof loginSchema>,
    deviceInfo?: any
  ): Promise<LoginResponse> {
    const validatedData = loginSchema.parse(data);

    // Find user with profile
    const user = await prisma.user.findUnique({
      where: { email: validatedData.email.toLowerCase() },
      include: { profile: true },
    });

    if (!user) {
      throw new Error("Invalid credentials");
    }

    // Check if account is locked
    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
      const remainingTime = Math.ceil(
        (user.lockoutUntil.getTime() - Date.now()) / (1000 * 60)
      );
      throw new Error(`Account locked. Try again in ${remainingTime} minutes`);
    }

    // Check if account is active
    if (user.status !== UserStatus.ACTIVE) {
      throw new Error("Account is not active");
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(
      validatedData.password,
      user.password
    );

    if (!isPasswordValid) {
      // Increment login attempts
      await this.handleFailedLogin(user.id);
      throw new Error("Invalid credentials");
    }

    // Reset login attempts on successful login
    await this.handleSuccessfulLogin(user.id, deviceInfo);

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.role);

    // Create session
    await this.createSession(user.id, tokens.refreshToken, deviceInfo);

    return {
      user: this.sanitizeUser(user),
      tokens,
    };
  }

  // ========================================================================
  // TOKEN REFRESH
  // ========================================================================

  async refreshTokens(
    data: z.infer<typeof refreshTokenSchema>
  ): Promise<AuthTokens> {
    const { refreshToken } = refreshTokenSchema.parse(data);

    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, this.JWT_REFRESH_SECRET) as any;

      // Check if session exists and is active
      const session = await prisma.userSession.findUnique({
        where: { token: refreshToken },
        include: { user: true },
      });

      if (!session || !session.isActive || session.expiresAt < new Date()) {
        throw new Error("Invalid refresh token");
      }

      // Check if user is still active
      if (session.user.status !== UserStatus.ACTIVE) {
        throw new Error("User account is not active");
      }

      // Generate new tokens
      const newTokens = await this.generateTokens(
        session.user.id,
        session.user.role
      );

      // Update session with new refresh token
      await prisma.userSession.update({
        where: { id: session.id },
        data: {
          token: newTokens.refreshToken,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          lastUsedAt: new Date(),
        },
      });

      return newTokens;
    } catch (error) {
      throw new Error("Invalid refresh token");
    }
  }

  // ========================================================================
  // LOGOUT
  // ========================================================================

  async logout(refreshToken: string): Promise<void> {
    await prisma.userSession.updateMany({
      where: { token: refreshToken },
      data: { isActive: false },
    });
  }

  async logoutAll(userId: string): Promise<void> {
    await prisma.userSession.updateMany({
      where: { userId },
      data: { isActive: false },
    });
  }

  // ========================================================================
  // TOKEN VERIFICATION
  // ========================================================================

  async verifyAccessToken(token: string): Promise<AuthUser> {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET) as any;

      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        include: { profile: true },
      });

      if (!user || user.status !== UserStatus.ACTIVE) {
        throw new Error("User not found or inactive");
      }

      return this.sanitizeUser(user);
    } catch (error) {
      throw new Error("Invalid access token");
    }
  }

  // ========================================================================
  // PASSWORD MANAGEMENT
  // ========================================================================

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      throw new Error("User not found");
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password
    );

    if (!isCurrentPasswordValid) {
      throw new Error("Current password is incorrect");
    }

    // Validate new password
    const passwordSchema = z
      .string()
      .min(8, "Password must be at least 8 characters")
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
        "Password must contain uppercase, lowercase, number, and special character"
      );

    passwordSchema.parse(newPassword);

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(
      newPassword,
      parseInt(process.env.BCRYPT_ROUNDS || "12")
    );

    // Update password and invalidate all sessions
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: { password: hashedNewPassword },
      }),
      prisma.userSession.updateMany({
        where: { userId },
        data: { isActive: false },
      }),
    ]);
  }

  // ========================================================================
  // PRIVATE HELPER METHODS
  // ========================================================================

  private async generateTokens(
    userId: string,
    role: UserRole
  ): Promise<AuthTokens> {
    const accessTokenPayload = {
      userId,
      role,
      type: "access",
    };

    const refreshTokenPayload = {
      userId,
      role,
      type: "refresh",
    };

    const accessToken = jwt.sign(accessTokenPayload, this.JWT_SECRET, {
      expiresIn: this.ACCESS_TOKEN_EXPIRES,
    });

    const refreshToken = jwt.sign(
      refreshTokenPayload,
      this.JWT_REFRESH_SECRET,
      {
        expiresIn: this.REFRESH_TOKEN_EXPIRES,
      }
    );

    // Calculate expiration time in seconds for frontend
    const expiresIn = 15 * 60; // 15 minutes in seconds

    return { accessToken, refreshToken, expiresIn };
  }

  private async createSession(
    userId: string,
    refreshToken: string,
    deviceInfo?: any
  ): Promise<void> {
    await prisma.userSession.create({
      data: {
        userId,
        token: refreshToken,
        deviceInfo: deviceInfo || {},
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      },
    });
  }

  private async handleFailedLogin(userId: string): Promise<void> {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) return;

    const loginAttempts = user.loginAttempts + 1;
    const shouldLockAccount = loginAttempts >= this.MAX_LOGIN_ATTEMPTS;

    await prisma.user.update({
      where: { id: userId },
      data: {
        loginAttempts,
        lockoutUntil: shouldLockAccount
          ? new Date(Date.now() + this.LOCKOUT_DURATION)
          : null,
      },
    });
  }

  private async handleSuccessfulLogin(
    userId: string,
    deviceInfo?: any
  ): Promise<void> {
    await prisma.user.update({
      where: { id: userId },
      data: {
        loginAttempts: 0,
        lockoutUntil: null,
        lastLogin: new Date(),
      },
    });
  }

  private sanitizeUser(user: any): AuthUser {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      status: user.status,
      profile: user.profile
        ? {
            firstName: user.profile.firstName,
            lastName: user.profile.lastName,
            displayName: user.profile.displayName,
          }
        : null,
    };
  }

  // ========================================================================
  // SESSION MANAGEMENT
  // ========================================================================

  async getActiveSessions(userId: string) {
    return prisma.userSession.findMany({
      where: {
        userId,
        isActive: true,
        expiresAt: { gt: new Date() },
      },
      select: {
        id: true,
        deviceInfo: true,
        createdAt: true,
        lastUsedAt: true,
      },
    });
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    await prisma.userSession.updateMany({
      where: {
        id: sessionId,
        userId, // Ensure user can only revoke their own sessions
      },
      data: { isActive: false },
    });
  }

  // ========================================================================
  // PROFILE MANAGEMENT
  // ========================================================================

  async updateProfile(userId: string, updateData: any) {
    // Validate update data
    const updateProfileSchema = z.object({
      firstName: z.string().min(2).optional(),
      lastName: z.string().min(2).optional(),
      displayName: z.string().optional(),
      phone: z.string().optional(),
      alternatePhone: z.string().optional(),
      dateOfBirth: z.string().datetime().optional(),
      gender: z
        .enum(["MALE", "FEMALE", "OTHER", "PREFER_NOT_TO_SAY"])
        .optional(),
      bio: z.string().max(500).optional(),
      address: z.any().optional(), // JSON object
    });

    const validatedData = updateProfileSchema.parse(updateData);

    // Update display name if first/last name changed
    if (validatedData.firstName || validatedData.lastName) {
      const currentProfile = await prisma.userProfile.findUnique({
        where: { userId },
      });

      if (currentProfile) {
        validatedData.displayName = `${
          validatedData.firstName || currentProfile.firstName
        } ${validatedData.lastName || currentProfile.lastName}`;
      }
    }

    // Convert dateOfBirth string to Date if provided
    if (validatedData.dateOfBirth) {
      (validatedData as any).dateOfBirth = new Date(validatedData.dateOfBirth);
    }

    return await prisma.userProfile.update({
      where: { userId },
      data: validatedData,
    });
  }

  // ========================================================================
  // EMAIL VERIFICATION
  // ========================================================================

  async verifyEmail(token: string) {
    const user = await prisma.user.findFirst({
      where: { emailVerificationToken: token },
      include: { profile: true },
    });

    if (!user) {
      throw new Error("Invalid verification token");
    }

    // Update user as verified
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
      },
      include: { profile: true },
    });

    return this.sanitizeUser(updatedUser);
  }

  async resendEmailVerification(userId: string): Promise<void> {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      throw new Error("User not found");
    }

    if (user.emailVerified) {
      throw new Error("Email is already verified");
    }

    // Generate new verification token
    const verificationToken = jwt.sign(
      { userId, email: user.email, type: "email_verification" },
      this.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Update user with new token
    await prisma.user.update({
      where: { id: userId },
      data: { emailVerificationToken: verificationToken },
    });

    // TODO: Send email with verification link
    console.log(
      `📧 Send verification email to ${user.email} with token: ${verificationToken}`
    );
  }

  // ========================================================================
  // PASSWORD RESET
  // ========================================================================

  async forgotPassword(email: string): Promise<void> {
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    // Don't reveal if user exists for security
    if (!user) {
      return;
    }

    // Generate reset token
    const resetToken = jwt.sign(
      { userId: user.id, email: user.email, type: "password_reset" },
      this.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Save reset token and expiry
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: resetToken,
        passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      },
    });

    // TODO: Send email with reset link
    console.log(
      `📧 Send password reset email to ${user.email} with token: ${resetToken}`
    );
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    try {
      // Verify reset token
      const decoded = jwt.verify(token, this.JWT_SECRET) as any;

      if (decoded.type !== "password_reset") {
        throw new Error("Invalid token type");
      }

      // Find user with valid reset token
      const user = await prisma.user.findFirst({
        where: {
          id: decoded.userId,
          passwordResetToken: token,
          passwordResetExpires: { gt: new Date() },
        },
      });

      if (!user) {
        throw new Error("Invalid or expired reset token");
      }

      // Validate new password
      const passwordSchema = z
        .string()
        .min(8, "Password must be at least 8 characters")
        .regex(
          /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
          "Password must contain uppercase, lowercase, number, and special character"
        );

      passwordSchema.parse(newPassword);

      // Hash new password
      const hashedPassword = await bcrypt.hash(
        newPassword,
        parseInt(process.env.BCRYPT_ROUNDS || "12")
      );

      // Update password and clear reset token
      await prisma.$transaction([
        prisma.user.update({
          where: { id: user.id },
          data: {
            password: hashedPassword,
            passwordResetToken: null,
            passwordResetExpires: null,
          },
        }),
        // Invalidate all sessions for security
        prisma.userSession.updateMany({
          where: { userId: user.id },
          data: { isActive: false },
        }),
      ]);
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error("Invalid reset token");
      }
      throw error;
    }
  }

  // ========================================================================
  // UTILITY METHODS
  // ========================================================================

  async checkEmailAvailability(email: string): Promise<boolean> {
    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    return !existingUser;
  }

  async getUserStats() {
    const stats = await prisma.user.groupBy({
      by: ["role", "status"],
      _count: {
        id: true,
      },
    });

    const totalUsers = await prisma.user.count();
    const verifiedUsers = await prisma.user.count({
      where: { emailVerified: true },
    });
    const activeUsers = await prisma.user.count({
      where: { status: "ACTIVE" },
    });

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const newUsersToday = await prisma.user.count({
      where: {
        createdAt: { gte: today },
      },
    });

    const activeSessions = await prisma.userSession.count({
      where: {
        isActive: true,
        expiresAt: { gt: new Date() },
      },
    });

    return {
      totalUsers,
      verifiedUsers,
      activeUsers,
      newUsersToday,
      activeSessions,
      usersByRole: stats.reduce((acc: any, stat: any) => {
        acc[stat.role] = (acc[stat.role] || 0) + stat._count.id;
        return acc;
      }, {}),
      usersByStatus: stats.reduce((acc: any, stat: any) => {
        acc[stat.status] = (acc[stat.status] || 0) + stat._count.id;
        return acc;
      }, {}),
    };
  }

  // ========================================================================
  // CLEANUP EXPIRED SESSIONS
  // ========================================================================

  async cleanupExpiredSessions(): Promise<void> {
    await prisma.userSession.deleteMany({
      where: {
        OR: [{ expiresAt: { lt: new Date() } }, { isActive: false }],
      },
    });
  }
}

export const authService = new AuthService();
