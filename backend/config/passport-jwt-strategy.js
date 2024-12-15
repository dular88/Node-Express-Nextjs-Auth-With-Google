import UserModel from "../models/User.js";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import passport from "passport";

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
};

passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await UserModel.findOne({ _id: jwt_payload._id }).select("-password");
      if (user) {
        return done(null, user); // Successfully authenticated user
      } else {
        return done(null, false); // No user found
      }
    } catch (error) {
      console.error("Error during JWT authentication:", error); // Log the error
      return done(error, false); // Error during authentication
    }
  })
);

export default passport;
