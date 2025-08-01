import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import rateLimit from "express-rate-limit";

// Import routes
import routes from "./routes/index.ts";

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

// CORS configuration
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? process.env.ALLOWED_ORIGINS?.split(",") || ["https://your-domain.com"]
        : ["http://localhost:3000", "http://localhost:3001"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

// Compression
app.use(compression());

// ============================================================================
// RATE LIMITING
// ============================================================================

const globalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.RATE_LIMIT_MAX_REQUESTS
    ? parseInt(process.env.RATE_LIMIT_MAX_REQUESTS)
    : 1000, // requests per window
  message: {
    success: false,
    error: "Too many requests from this IP, please try again later",
    code: "RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use forwarded IP if behind proxy, otherwise use connection IP
    return req.ip || req.connection.remoteAddress || "unknown";
  },
});

app.use(globalRateLimit);

// ============================================================================
// LOGGING
// ============================================================================

// Custom logging format
morgan.token("user-id", (req: any) => {
  return req.user ? req.user.id : "anonymous";
});

morgan.token("user-role", (req: any) => {
  return req.user ? req.user.role : "none";
});

const logFormat =
  process.env.NODE_ENV === "production"
    ? "combined"
    : ":method :url :status :res[content-length] - :response-time ms [:user-id] [:user-role]";

app.use(morgan(logFormat));

// ============================================================================
// BODY PARSING
// ============================================================================

app.use(
  express.json({
    limit: process.env.MAX_FILE_SIZE || "10mb",
    verify: (req, res, buf) => {
      // Store raw body for webhook verification if needed
      (req as any).rawBody = buf;
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: process.env.MAX_FILE_SIZE || "10mb",
  })
);

// ============================================================================
// TRUST PROXY (For deployment behind reverse proxy)
// ============================================================================

if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", 1);
}

// ============================================================================
// ROUTES
// ============================================================================

// Mount all routes
app.use(routes);

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "🎓 Acurve College Management System API",
    version: "1.0.0",
    environment: process.env.NODE_ENV || "development",
    documentation: "/api/v1",
    status: "🚀 Running",
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 Handler
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.originalUrl} not found`,
    code: "ROUTE_NOT_FOUND",
    suggestion: "Check the API documentation at /api/v1",
  });
});

// Global Error Handler
app.use(
  (
    err: any,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    console.error("❌ Unhandled Error:", err);

    // Don't leak error details in production
    const isDev = process.env.NODE_ENV === "development";

    res.status(err.status || 500).json({
      success: false,
      error: isDev ? err.message : "Internal server error",
      code: err.code || "INTERNAL_ERROR",
      ...(isDev && { stack: err.stack }),
      timestamp: new Date().toISOString(),
    });
  }
);

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

const gracefulShutdown = (signal: string) => {
  console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);

  // Close server
  server.close(() => {
    console.log("✅ HTTP server closed.");

    // Close database connections, cleanup resources, etc.
    process.exit(0);
  });

  // Force close after 10 seconds
  setTimeout(() => {
    console.error(
      "❌ Could not close connections in time, forcefully shutting down"
    );
    process.exit(1);
  }, 10000);
};

// Listen for shutdown signals
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
  // Don't exit the process in production, just log
  if (process.env.NODE_ENV === "development") {
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error);
  process.exit(1);
});

// ============================================================================
// START SERVER
// ============================================================================

const server = app.listen(PORT, () => {
  console.log("🚀 Acurve Backend Server Started!");
  console.log(`📍 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`🌐 Server running on: http://localhost:${PORT}`);
  console.log(`📋 API Documentation: http://localhost:${PORT}/api/v1`);
  console.log(`❤️  Health Check: http://localhost:${PORT}/api/v1/health`);
  console.log(`🔐 Auth Endpoint: http://localhost:${PORT}/api/v1/auth`);

  if (process.env.NODE_ENV === "development") {
    console.log("\n🔧 Development Mode Features:");
    console.log("   • Detailed error messages");
    console.log("   • Request logging with user info");
    console.log("   • Relaxed CORS policy");
  }

  console.log("\n" + "=".repeat(60));
});

export default app;
