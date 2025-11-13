import { Response, NextFunction, Request } from "express";
import mongoose from "mongoose";
import jwt, { JwtPayload } from "jsonwebtoken";
import Vendor, { IVendor } from "../models/vendor";

interface AuthRequest extends Request {
    user?: { _id: string; email: string };
}


export const authVendor = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).send({ success: false, message: "No token provided" });
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

        const vendor = await Vendor.findOne({
            _id: new mongoose.Types.ObjectId(decoded._id),
            isDeleted: false,
            tokens: { $in: [token] },
        }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(401).send({
                success: false,
                message: "Session expired. Please login again.",
            });
        }

        if (['pending', 'rejected'].includes(vendor.status)) {
            return res.status(400).send({
                success: false,
                message: vendor.status === 'pending' ? 'Your request is still pending. Please contact the administrator for assistance.' : "Your request has been rejected. Please contact the administrator for further assistance",
            });
        }

        req.user = { _id: decoded._id, email: decoded.email };

        next();
    } catch (error) {
        return res.status(401).send({ success: false, message: "Invalid or expired token" });
    }
};
