const setTokenCookies = (res, accessToken, refreshToken, newAccessTokenExp, newRefreshTokenExp) => {
    console.log("Type of res:", typeof res);
    console.log("res methods:", Object.keys(res));
  
    const accessTokenMaxAge = (newAccessTokenExp - Math.floor(Date.now() / 1000)) * 1000;
    const refreshTokenMaxAge = (newRefreshTokenExp - Math.floor(Date.now() / 1000)) * 1000;
  
    if (typeof res.cookie !== "function") {
      throw new Error("Invalid response object passed to setTokenCookies.");
    }
  
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: accessTokenMaxAge,
    });
  
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: refreshTokenMaxAge,
    });
  };
  
  export default setTokenCookies;
  