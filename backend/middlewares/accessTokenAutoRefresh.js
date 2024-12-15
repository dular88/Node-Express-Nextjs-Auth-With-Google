import jwt from 'jsonwebtoken';

const accessTokenAutoRefresh = (req, res, next) => {
    const accessToken = req.cookies.accessToken; // Assuming the access token is stored in cookies

    if (!accessToken) {
        return res.status(401).json({ error: true, message: "Access token is missing" });
    }

    try {
        // Verify the access token
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        
        // Attach user to request object
        req.user = decoded;
        next(); // Call next middleware or route handler
    } catch (err) {
        return res.status(401).json({ error: true, message: "Invalid or expired access token" });
    }
};

export default accessTokenAutoRefresh;
