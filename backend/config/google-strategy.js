import { Strategy as GoogleStrategy } from 'passport-google-oauth2';
import passport from "passport";
import UserModel from "../models/User.js";
import generateTokens from '../utils/generateToken.js';

passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
    passReqToCallback   : true
  },
  async (request, accessToken, refreshToken, profile, done) =>{
try {
       let user =await UserModel.findOne({email:profile._json.email});
       if(!user){
        const lastSixDigitID = profile.id.substring(profile.id.length - 6);
        const lastTwoDigitsName = profile._json.name.substring(profile._json.name.length - 2);
        const newPass = lastTwoDigitsName + lastSixDigitID;

        const salt = await bcrypt .genSalt(Number(process.env.SALT));
        const hashedPassword = await bcrypt.hash(newPass, salt);
      user =   await UserModel.create({
            name: profile._json.name,
            email:profile._json.email,
            is_verified: true,
            password: hashedPassword
        })
       }

       const {accessToken, refreshToken, accessTokenExp, refreshTokenExp } =await generateTokens(user);
       return done(null, {user,accessToken,refreshToken,accessTokenExp,refreshTokenExp}); 
} catch (error) {
    return done(error);
}
  }
));