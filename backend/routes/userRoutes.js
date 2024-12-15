import express from "express";
import passport from "passport";
import UserController from "../controllers/userController.js";
import accessTokenAutoRefresh from "../middlewares/accessTokenAutoRefresh.js";


// Ensure the Passport JWT strategy is loaded before the routes are used
import "../config/passport-jwt-strategy.js"; // Correct import path for passport-jwt-strategy.js



const router = express.Router();

// User authentication and profile routes
router.post("/register", UserController.userRegistration);
router.post("/verify-email", UserController.verifyEmail);
router.post("/login", UserController.userLogin);
router.post("/refresh-token", UserController.getNewAccessToken);
router.post("/reset-password-link", UserController.sendUserPasswordResetEmail);
router.post("/reset-password/:id/:token", UserController.userPasswordReset);

router.get(
  "/me",
  accessTokenAutoRefresh,
  passport.authenticate("jwt", { session: false }),
  UserController.userProfile
);

router.post(
  "/change-password",
  accessTokenAutoRefresh,
  passport.authenticate("jwt", { session: false }),
  UserController.changeUserPassword
);

router.post(
  "/logout",
  accessTokenAutoRefresh,
  passport.authenticate("jwt", { session: false }),
  UserController.userLogout
);

export default router;
