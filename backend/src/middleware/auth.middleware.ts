// src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from "express";
import { UserRole } from "../generated/prisma/index.js";
import { authService } from "../services/auth.service.js";

// ============================================================================
// EXTEND EXPRESS REQUEST TYPE
// ============================================================================

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: UserRole;
        status: string;
        profile: {
          firstName: string;
          lastName: string;
          displayName: string | null;
        } | null;
      };
    }
  }
}

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({
        success: false,
        error: "Access token required",
        code: "MISSING_TOKEN",
      });
      return;
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix

    try {
      const user = await authService.verifyAccessToken(token);
      req.user = user;
      next();
    } catch (error) {
      res.status(401).json({
        success: false,
        error: "Invalid or expired token",
        code: "INVALID_TOKEN",
      });
      return;
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Authentication error",
      code: "AUTH_ERROR",
    });
    return;
  }
};

// ============================================================================
// ROLE-BASED ACCESS CONTROL
// ============================================================================

export const authorize = (...allowedRoles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "Authentication required",
        code: "NOT_AUTHENTICATED",
      });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        success: false,
        error: "Insufficient permissions",
        code: "INSUFFICIENT_PERMISSIONS",
        required: allowedRoles,
        current: req.user.role,
      });
      return;
    }

    next();
  };
};

// ============================================================================
// ROLE HIERARCHY AUTHORIZATION
// ============================================================================

const roleHierarchy: Record<UserRole, number> = {
  [UserRole.SUPER_ADMIN]: 100,
  [UserRole.ADMIN]: 80,
  [UserRole.FACULTY]: 60,
  [UserRole.STAFF]: 40,
  [UserRole.STUDENT]: 20,
  [UserRole.PARENT]: 10,
};

export const authorizeMinRole = (minRole: UserRole) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "Authentication required",
        code: "NOT_AUTHENTICATED",
      });
      return;
    }

    const userRoleLevel = roleHierarchy[req.user.role];
    const minRoleLevel = roleHierarchy[minRole];

    if (userRoleLevel < minRoleLevel) {
      res.status(403).json({
        success: false,
        error: "Insufficient permissions",
        code: "INSUFFICIENT_PERMISSIONS",
        required: `Minimum role: ${minRole}`,
        current: req.user.role,
      });
      return;
    }

    next();
  };
};

// ============================================================================
// RESOURCE OWNERSHIP AUTHORIZATION
// ============================================================================

export const authorizeOwnershipOrRole = (
  resourceUserIdField: string = "userId",
  allowedRoles: UserRole[] = [UserRole.ADMIN, UserRole.SUPER_ADMIN]
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: "Authentication required",
        code: "NOT_AUTHENTICATED",
      });
      return;
    }

    // Check if user has elevated role
    if (allowedRoles.includes(req.user.role)) {
      next();
      return;
    }

    // Check ownership
    const resourceUserId =
      req.params[resourceUserIdField] || req.body[resourceUserIdField];

    if (!resourceUserId) {
      res.status(400).json({
        success: false,
        error: `Missing ${resourceUserIdField} parameter`,
        code: "MISSING_RESOURCE_ID",
      });
      return;
    }

    if (req.user.id !== resourceUserId) {
      res.status(403).json({
        success: false,
        error: "Can only access your own resources",
        code: "OWNERSHIP_REQUIRED",
      });
      return;
    }

    next();
  };
};

// ============================================================================
// OPTIONAL AUTHENTICATION
// ============================================================================

export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // No token provided, continue without authentication
    next();
    return;
  }

  const token = authHeader.substring(7);

  try {
    const user = await authService.verifyAccessToken(token);
    req.user = user;
  } catch (error) {
    // Invalid token, but continue without authentication
    // You might want to log this for security monitoring
  }

  next();
};

// ============================================================================
// ACCOUNT STATUS CHECKS
// ============================================================================

export const requireActiveAccount = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: "Authentication required",
      code: "NOT_AUTHENTICATED",
    });
    return;
  }

  if (req.user.status !== "ACTIVE") {
    res.status(403).json({
      success: false,
      error: "Account is not active",
      code: "ACCOUNT_INACTIVE",
      status: req.user.status,
    });
    return;
  }

  next();
};

// ============================================================================
// RATE LIMITING HELPERS
// ============================================================================

export const getRateLimitKey = (req: Request): string => {
  // Use user ID if authenticated, otherwise use IP
  return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
};

// ============================================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================================

export const securityHeaders = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Remove sensitive headers
  res.removeHeader("X-Powered-By");

  // Add security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // CORS headers are handled by the cors middleware

  next();
};

// ============================================================================
// AUDIT LOGGING MIDDLEWARE
// ============================================================================

export const auditLog = (action: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Store audit info in res.locals for later logging
    res.locals.auditInfo = {
      action,
      userId: req.user?.id,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      timestamp: new Date(),
      resource: req.originalUrl,
    };

    next();
  };
};

// ============================================================================
// COMPOSITE MIDDLEWARE HELPERS
// ============================================================================

// Common auth patterns
export const studentOnly = [authenticate, authorize(UserRole.STUDENT)];
export const facultyOnly = [authenticate, authorize(UserRole.FACULTY)];
export const adminOnly = [
  authenticate,
  authorize(UserRole.ADMIN, UserRole.SUPER_ADMIN),
];
export const staffOrAdmin = [
  authenticate,
  authorize(UserRole.STAFF, UserRole.ADMIN, UserRole.SUPER_ADMIN),
];
export const facultyOrAdmin = [
  authenticate,
  authorize(UserRole.FACULTY, UserRole.ADMIN, UserRole.SUPER_ADMIN),
];

// Role hierarchy patterns
export const minFaculty = [authenticate, authorizeMinRole(UserRole.FACULTY)];
export const minAdmin = [authenticate, authorizeMinRole(UserRole.ADMIN)];

// Full auth with active account check
export const fullAuth = [authenticate, requireActiveAccount];
export const fullAuthAdmin = [
  authenticate,
  requireActiveAccount,
  authorize(UserRole.ADMIN, UserRole.SUPER_ADMIN),
];
