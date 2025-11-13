import { Response, NextFunction, Request } from "express";
import mongoose from "mongoose";
import jwt, { JwtPayload } from "jsonwebtoken";
import Admin, { IAdmin } from "../models/admin";

interface AuthRequest extends Request {
    user?: { _id: string; email: string };
}

export const authAdmin = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, message: "No token provided" });
        }

        const token = authHeader.split(" ")[1];
        const secret = process.env.JWT_SECRET;

        if (!secret) {
            throw new Error("JWT_SECRET is not defined in environment variables");
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload & {
            _id: string;
            email: string;
        };

        const admin = await Admin.findOne({
            _id: new mongoose.Types.ObjectId(decoded._id),
            isDeleted: false,
            tokens: { $in: [token] },
        }).lean<IAdmin | null>();

        if (!admin) {
            return res.status(401).json({
                success: false,
                message: "Session expired. Please login again.",
            });
        }

        req.user = { _id: decoded._id, email: decoded.email };

        next();
    } catch (error) {
        console.error("Auth Error:", error);
        return res
            .status(401)
            .json({ success: false, message: "Invalid or expired token" });
    }
};
