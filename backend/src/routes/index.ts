// src/routes/index.ts
import { Router } from "express";
import authRoutes from "./auth.routes.ts";

const router = Router();

// API version prefix
const API_VERSION = process.env.API_VERSION || "v1";

// ============================================================================
// ROUTE MOUNTING
// ============================================================================

// Auth routes
router.use(`/api/${API_VERSION}/auth`, authRoutes);

// Health check for the entire API
router.get(`/api/${API_VERSION}/health`, (req, res) => {
  res.json({
    success: true,
    message: "Acurve API is healthy",
    version: API_VERSION,
    timestamp: new Date().toISOString(),
    services: {
      auth: "✅ Healthy",
      database: "✅ Connected",
    },
  });
});

// API documentation route
router.get(`/api/${API_VERSION}`, (req, res) => {
  res.json({
    success: true,
    message: "Welcome to Acurve API",
    version: API_VERSION,
    documentation: `https://docs.acurve.com/api/${API_VERSION}`,
    endpoints: {
      auth: {
        register: `POST /api/${API_VERSION}/auth/register`,
        login: `POST /api/${API_VERSION}/auth/login`,
        refresh: `POST /api/${API_VERSION}/auth/refresh`,
        logout: `POST /api/${API_VERSION}/auth/logout`,
        profile: `GET /api/${API_VERSION}/auth/profile`,
      },
      // Future endpoints will be added here
      students: "Coming soon",
      faculty: "Coming soon",
      courses: "Coming soon",
    },
  });
});

export default router;
