import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

export const isLogin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      console.log("❌ isLogin: Missing or invalid Authorization header");
      return res.status(401).json({
        success: false,
        message: "Could not find authentication token. Please log in again."
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      console.log("❌ isLogin: Token missing after split");
      return res.status(401).json({ success: false, message: "Token missing" });
    }

    const decoded = jwt.verify(token, process.env.JWT_TOKEN);

    // Find user and attach to request (exclude password)
    const user = await User.findById(decoded.id || decoded._id).select("-password");

    if (!user) {
      console.log("❌ isLogin: User not found for token ID:", decoded.id || decoded._id);
      return res.status(401).json({ success: false, message: "User not found" });
    }

    // console.log("✅ isLogin: User authenticated:", user._id);
    req.user = user;
    next();
  } catch (error) {
    console.error("Auth Middleware Error:", error.message);
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
};