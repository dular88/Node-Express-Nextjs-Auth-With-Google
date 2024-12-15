
import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import sendEmailNotificationOtp from "../utils/sendEmailNotificationOtp.js";
import EmailVerificationModel from "../models/emailVerification.js";
import generateTokens from "../utils/generateToken.js";
import setTokenCookies from "../utils/setTokensCookies.js";
import refreshAccessToken from "../utils/refreshAccessToken.js";
import UserRefreshTokenModel from "../models/UserRefreshToken.js";
import transporter from "../config/emailConfig.js";
import jwt from "jsonwebtoken";

class UserController{

    static userRegistration = async (req, res)=>{
        try {
            const {name, email, password, password_confirmation} =req.body;
            
            if(!name || !email || !password || !password_confirmation){
                return res.status(400).json({status:"failed",message:"All fields are required !!!"});
            }

            if(password !== password_confirmation){
                return res.status(400).json({status:"failed", message:"Password and Confirm password don't match"});
            }

            const existingUser = await UserModel.findOne({email});
            if(existingUser){
                return res.status(409).json({status:"failed", message:"Email Already exists"});
            }

            const salt = await bcrypt.genSalt(Number(process.env.SALT));
            const hashedPassword = await bcrypt.hash(password, salt);

            const newUser = await new UserModel({
                name, email, password: hashedPassword
            }).save();

            sendEmailNotificationOtp(req, newUser);

            res.status(201).json({status:"success", message:"Registration Success", user:{id:newUser._id, email: newUser.email}})
        } catch (error) {
            console.error(error);
            res.status(500).json({status:"failed",message:"Unable to register, please try again"});
        }
    }

    static verifyEmail = async (req, res) =>{
        try {
            const {email, otp} = req.body;

            if(!email || !otp){
                return res.status(400).json({status: "failed", message: "All fields are required"});
            }

            const existingUser = await UserModel.findOne({email});
            if(!existingUser){
                return res.status(404).json({status: "failed", message: "Email doesn't exists"});
            }

            if(existingUser.is_verified){
                return res.status(400).json({status: "failed", message: "Email is already verified"});
            }

            const emailVerification = await EmailVerificationModel.findOne({userId: existingUser._id, otp});

            if(!emailVerification){
                if(!existingUser.is_verified){
                    await sendEmailVerificationOtp(req, existingUser);
                    return res.status(400).json({status: "failed", message: "Invalid OTP, new OTP sent to your email"});
                }
                return res.status(400).json({status: "failed", message: "Invalid OTP"});
            }

            const currentTime = new Date();
            const expirationTime = new Date(emailVerification.createdAt.getTime() + 15*60*1000);

            if(currentTime > expirationTime){
                await sendEmailVerificationOtp(req, existingUser);
                res.status(400).json({status:"failed", message:"OTP expired, new OTPsent to your email"});
            }

            existingUser.is_verified = true;
            await existingUser.save();

            await EmailVerificationModel.deleteMany({userId : existingUser._id});
            return res.status(200).json({status:"success", message: "Email verified successfully"});
             
        } catch (error) {
            console.error(error);
            res.status(500).json({type: "failed", message: "Unable to verify email, please try again"});
        }
    }

    static userLogin = async (req, res) =>{
        try {
            const {email, password} = req.body;
            if(!email || !password){
                return res.status(400).json({status: "failed", message: "Email and password are required"});
            }

            const user = await UserModel.findOne({email});

            if(!user){
                return res.status(404).json({status:"failed", message: "Invalid email or password"});
            }

            if(!user.is_verified){
                return res.status(401).json({status:"failed", message:"Your account is not verified"});
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if(!isMatch){
                return res.status(401).json({status:"failed", message:"Invalid email or password"});
            }

            const {accessToken, refreshToken, accessTokenExp, refreshTokenExp} = await generateTokens(user);
            
            setTokenCookies(res,accessToken, refreshToken, accessTokenExp, refreshTokenExp);

            res.status(200).json({
                user: {id: user._id, email: user.email, name: user.name, roles: user.roles[0]},
                status: "success",
                message: "Login Successful",
                access_token: accessToken,
                refresh_token: refreshToken,
                access_token_exp: accessTokenExp,
                is_auth: true
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({status: "failed", message: "Unable to login, please try again later"});
        }
    }

    static getNewAccessToken = async (req, res)=>{
        try {
            const {newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp} = await refreshAccessToken(req, res);
            setTokenCookies(res, newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp);

            res.status(200).json({
                status: "success", 
                message: "New token generated",
                access_token: newAccessToken,
                refresh_token: newRefreshToken,
                access_token_exp: newAccessTokenExp
            });

        } catch (error) {
            console.error(error);
            res.status(500).json({status:"failed", message: "Unable to generate new token, please try again later"});
        }
    }

    static userProfile = async (req, res) =>{
        console.log(req.user);
        res.send({ "user": req.user });
    }

    static changeUserPassword = async (req, res)=>{
        try {
            const { password, password_confirmation } = req.body;
            if(!password || !password_confirmation) {
                return res.status(400).json({ status:"failed", message: "New password and confirm password are required" });
            }

            const salt = await bcrypt.genSalt(10);
            const newHashPassword = await bcrypt.hash(password, salt);

            await UserModel.findByIdAndUpdate(req.user._id, { $set: {password: newHashPassword}});

            res.status(200).json({status:"success", message: "Password changed successfully"});
        } catch (error) {
            console.error(error);
            res.status(500).json({status: "failed", message: "Unable to change password, please try again later"});
        }
    }

    static sendUserPasswordResetEmail = async (req, res) =>{
        try {
            const {email} = req.body;
            if(!email){
                return res.status(400).json({status: "failed", message: "Email is required"});
            }

            const user = await UserModel.findOne({email});
            if(!user){
                return res.status(404).json({status: "failed", message: "Email doesn't exist"});
            }

            const secret = user._id + process.env.JWT_ACCESS_TOKEN_SECRET_KEY;
            const token = jwt.sign({ userId: user._id }, secret, { expiresIn: "15m"});

            const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password-confirm/${user._id}/${token}`;

            await transporter.sendMail({
                from: process.env.EMAIL_FROM,
                to:user.email,
                subject: "Password reset link",
                html: `<p>Hello ${user.name},</p><p>Please <a href="${resetLink}">Click here<a> to reset your password</p>`
            });

            res.status(200).json({status: "success", message: "Password reset email sent, please check your email"});
        } catch (error) {
            console.error(error);
            res.status(500).json({status: "failed", message: " Unable to send password reset email, please try again later"});
        }
    }

    static userPasswordReset = async (req, res) =>{
        try {
            const { password, password_confirmation } = req.body;
            const { id, token } = req.params;

            if(!password || !password_confirmation){
                return res.status(400).json({status: "failed", message: "New password and new confirm password are required"});
            }
            
            const user = await UserModel.findById(id);
            if(!user){
                return res.status(404).json({status: "failed", message: "User not found"});
            }

            const new_secret = user._id + process.env.JWT_ACCESS_TOKEN_SECRET_KEY;
            jwt.verify(token, new_secret);

            const salt = await bcrypt.genSalt(10);
            const newHashPassword = await bcrypt.hash(password, salt);

            await UserModel.findByIdAndUpdate(user._id, {$set: {password: newHashPassword} });

            res.status(200).json({status: "success", message: "Password reset successfully"});
        } catch (error) {
            if(error.name === "TokenExpiredError"){
                return res.status(400).json({status: "failed", message: "Token expired. Please request a new password reset link."})
            }
            return res.status(500).json({status: "failed", message: "Unable to reset password,  please try again later" });
        }
    }


    static userLogout = async (req, res) =>{
        try {
            const refreshToken = req.cookies.refreshToken;
            await UserRefreshTokenModel.findOneAndUpdate(
                {token: refreshToken},
                {$set: {blacklisted:true}}
            );

            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");
            res.clearCookie("is_auth");
            res.status(200).json({status: "success", message:"Logout successfuly"});
        } catch (error) {
            console.error(error);
            res.status(500).json({ status: "failed", message: "Unable to logout, please try again later"});
        }
    }
}

export default UserController;