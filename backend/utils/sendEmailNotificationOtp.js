import transporter from "../config/emailConfig.js";
import EmailVerificationModel from "../models/emailVerification.js";

const SendEmailNotificationOtp = async (req, user) => {
    const otp = Math.floor(1000 + Math.random() * 9000);

    await new EmailVerificationModel({userId: user._id, otp: otp}).save();

    const otpVerificationLink = `${process.env.FRONT_END_HOST}/account/verify-email`;

    await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: "OTP - Verify your account",
        html: `<p>Dear ${user.name}</p><p>Your OTP is ${otp}</p><p>Please put here ${otpVerificationLink}</p>`
    });
};

export default SendEmailNotificationOtp;