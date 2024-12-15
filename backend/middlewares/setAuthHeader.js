import isTokenExpire from "../utils/isTokenExpired.js";

const setAuthHeader = async (req, res, next) =>{
    try {
        const accessToken = req.cookies.accessToken;

        if(accessToken || !isTokenExpire(accessToken)){
            req.headers["authorization"] = `Bearer ${accessToken}`
        }
        next();
    } catch (error) {
        console.error("error",error.message);
    }
}

export default setAuthHeader;