import UserModel from "../models/User.js";
import UserRefreshTokenModel from "../models/UserRefreshToken.js";
import generateTokens from "./generateToken.js";
import verifyRefreshToken from "./verifyRefreshToken.js";

const refreshAccessToken = async (req, res)=>{
    try {
        const oldRefreshToken = req.cookies.refreshToken;
        const {tokenDetails, error} = await verifyRefreshToken(oldRefreshToken);
        if(error){
            return res.status(401).json({status:"failed", message: "Invalid refresh token"});
        }

        const user = await UserModel.findById(tokenDetails._id);
        if(!user){
            return res.status(404).json({status: "failed", message: "User not found"});
        }
        const userRefreshToken = await UserRefreshTokenModel.findOne({userId: tokenDetails._id});
        if(oldRefreshToken !== userRefreshToken.token || userRefreshToken.blacklisted){
            return res.status(401).json({status:"failed", message: "Unauthorised access"});
        }

        const {accessToken, refreshToken, accessTokenExp, refreshTokenExp} = await generateTokens(user);
        return {
            newAccessToken: accessToken,
            newRefreshToken: refreshToken,
            newaccessTokenExp: accessTokenExp,
            newRefreshTokenExp: refreshTokenExp
        };
        
    } catch (error) {
        console.error(error);
        res.status(500).json({status: "failed", message:"Internal server error"});
    }
}

export default refreshAccessToken;