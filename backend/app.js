import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/connectdb.js";
import passport from "passport";
import userRoutes from "./routes/userRoutes.js";
import setTokenCookies from "./utils/setTokensCookies.js";
import "./config/google-strategy.js";
const app = express();

const PORT = process.env.PORT;
const DATABASE_URL = process.env.DATABASE_URL;

const corsOptions = {
    origin: process.env.FRONT_END_HOST,
    credentials:true,
    optionSuccessStatus:200

}
app.use(cors(corsOptions));

connectDB(DATABASE_URL);
app.use(express.json());
app.use(passport.initialize());
app.use(cookieParser());

app.use("/api/user", userRoutes);

app.get('/auth/google',
    passport.authenticate('google', { session:false, scope:
        [ 'email', 'profile' ] }
  ));
  
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
      session: false,
      failureRedirect: `${process.env.FRONT_END_HOST}/account/login`,
    }),
    (req, res) => {
      console.log("req.user:", req.user); // Debug req.user
  
      const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = req.user || {};
  
      if (!accessToken || !refreshToken) {
        console.error("Missing tokens or user info.");
        return res.status(500).json({ error: "Authentication failed." });
      }
  
      // Ensure you're passing the Express `res` object
      setTokenCookies(res, accessToken, refreshToken, accessTokenExp, refreshTokenExp);
  
      res.redirect(`${process.env.FRONT_END_HOST}/user/profile`);
    }
  );
  

app.listen(PORT, ()=>{
    console.log(`Server is running on port ${PORT}`);
});