import { Request, response, Response } from 'express';
import mongoose from 'mongoose';
import jwt, { JwtPayload } from "jsonwebtoken";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import Vendor, { IVendor } from "../models/vendor";
import { hashPassword, capitalizeName, generateOTP, emailFormatter, phoneFormatter } from '../functions/common';
import { sendMail } from '../functions/mailer';
import { vendorValidationSchema, vendorLoginSchema, forgotPasswordSchema, changePasswordSchema, otpSchema, resetPasswordSchema } from "../validations/validations";
import { sendTwilioMessage } from '../functions/twilio';

export const register = async (req: Request, res: Response) => {
    try {

        const { error } = vendorValidationSchema.validate(req.body, { abortEarly: false });

        if (error) {
            return res.status(400).json({
                success: false,
                errors: error.details[0].message,
            });
        }

        const vendor = await Vendor.findOne({
            $or: [
                { email: emailFormatter(req.body.email) },
                { phone: phoneFormatter(req.body.phone) }
            ],
        }).lean<IVendor | null>();

        if (vendor && !vendor.isVerified) {
            await Vendor.deleteOne({ _id: vendor._id });
        }

        if (vendor && vendor.isVerified) {
            if (vendor.email === emailFormatter(req.body.email)) {
                return res.status(400).send({ message: "Email already exists" });
            }
            if (vendor.phone === phoneFormatter(req.body.phone)) {
                return res.status(400).send({ message: "Phone already exists" });
            }
        }

        if (req.body.password !== req.body.confirmPassword) {
            return res.status(400).send({ message: 'Password and Confirm Password does not match' });
        }


        const obj = {
            _id: new mongoose.Types.ObjectId(),
            age: parseInt(req.body.age, 10),
            dob: req.body.dob,
            email: emailFormatter(req.body.email),
            firstName: capitalizeName(req.body.firstName),
            lastName: capitalizeName(req.body.lastName),
            password: await hashPassword(req.body.password),
            phone: phoneFormatter(req.body.phone),
            pivaCode: req.body.pivaCode,
            referralCode: req.body.referralCode,
            shopName: req.body.shopName,
            address: {
                address: req.body.address,
                city: req.body.city,
                state: req?.body?.state,
                zipCode: req.body.zipCode,
            },
        };

        const data = await Vendor.create(obj)

        return res.status(200).send({ data: { id: data._id, email: data.email, phone: data.phone }, message: 'Vendor Registered Successfully' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const sendOTP = async (req: Request, res: Response) => {
    try {

        if (!['email', 'phone'].includes(req.params.response)) {
            return res.status(400).send({ message: 'Invalid Response' });
        }

        const vendor = await Vendor.findOne({
            _id: req.params.id,
            isDeleted: false
        }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(400).send({ message: 'Vendor not found' });
        }

        const otp = await generateOTP()

        if (req.params.response === 'email') {
            const mailVariable = {
                '%firstName%': vendor.firstName,
                '%lastName%': vendor.lastName,
                '%link%': `${process.env.URL}/jwt/verification/${String(vendor._id)}`,
            }

            sendMail('vendor-verify', mailVariable, vendor.email);
        } else {
            await Promise.all([
                sendTwilioMessage({ phone: vendor.phone, OTP: otp }),
                Vendor.updateOne({ _id: vendor._id }, { $set: { otp: otp } })
            ])
        }

        return res.status(200).send({ data: { id: vendor._id, response: req.params.response }, message: req.params.response === 'email' ? 'Email Sent Successfully' : 'Phone OTP Sent Successfully' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const verification = async (req: Request, res: Response) => {
    try {

        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: "Invalid Vendor id" });
        }

        const vendor = await Vendor.findOne({
            _id: req.params.id,
            isDeleted: false
        }).lean<IVendor | null>();

        if (!vendor || vendor.isVerified) {
            return res.status(400).send({ message: !vendor ? 'Vendor not found' : 'Vendor already verified' });
        }

        let updateObj: any = {};

        if (req?.params?.response === 'phone') {

            if (vendor?.otp !== String(req.body.otp)) {
                return res.status(400).send({ message: 'Invalid OTP' });
            }

            updateObj.$set = {
                isVerified: true,
                isPhoneVerified: true
            };

            updateObj.$unset = { otp: '' };

        } else {
            updateObj.$set = {
                isVerified: true,
                isEmailVerified: true
            };
        }

        Vendor.updateOne({ _id: req.params.id }, updateObj).then();

        return res.status(200).send({ message: req.params.response === 'phone' ? 'Phone Number Verified Successfully' : 'Email Verified Successfully' });

    } catch (error) {
        console.error(error);
        return res.status(500).send({ message: 'Internal Server Error' });
    }
}

export const login = async (req: Request, res: Response) => {
    try {

        const { error } = vendorLoginSchema.validate(req.body, { abortEarly: false });

        if (error) {
            return res.status(400).json({
                success: false,
                errors: error.details[0].message,
            });
        }

        const { email, password } = req.body;

        const vendor = await Vendor.findOne({
            email: emailFormatter(email),
            isDeleted: false
        }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, vendor.password);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        if (['pending', 'rejected'].includes(vendor.status)) {
            return res.status(400).json({
                success: false,
                message: vendor.status === 'pending' ? 'Your request is pending. Please contact the administrator for assistance.' : "Your request has been rejected. Please contact the administrator for further assistance",
            });
        }

        const token = jwt.sign({ _id: vendor._id, email: vendor.email }, process.env.JWT_SECRET as string, { expiresIn: "7d" });

        Vendor.updateOne({
            _id: vendor._id,
        }, {
            $push: {
                tokens: token,
            }
        }).then();

        return res.status(200).send({ data: token, message: 'Vendor Login Successfully' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const forgotPassword = async (req: Request, res: Response) => {
    try {

        const { error } = forgotPasswordSchema.validate(req.body, { abortEarly: false });

        if (error) {
            return res.status(400).json({
                success: false,
                errors: error.details[0].message,
            });
        }

        const { email } = req.body;

        const vendor = await Vendor.findOne({
            email: emailFormatter(email)
        }, { firstName: 1, lastName: 1, email: 1 }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(400).send({ message: "Email not found" });
        }

        const otp = await generateOTP()

        Vendor.updateOne({
            _id: vendor._id,
        }, { $set: { otp } }).then();

        const mailVariable = {
            '%firstName%': vendor.firstName,
            '%lastName%': vendor.lastName,
            '%otp%': String(otp),
        }

        sendMail('vendor-forgot-password', mailVariable, vendor.email);

        return res.status(200).send({ data: vendor._id, message: 'OTP sent successfully to your email' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const resendOTP = async (req: Request, res: Response) => {
    try {

        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: "Invalid Vendor id" });
        }

        const vendor = await Vendor.findOne({ _id: req.params.id }, { firstName: 1, lastName: 1, email: 1 }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(400).send({ errors: "Vendor not found" })
        }

        const otp = await generateOTP()

        const mailVariable = {
            '%firstName%': vendor.firstName,
            '%lastName%': vendor.lastName,
            '%otp%': String(otp),
        }

        sendMail('vendor-resent-otp', mailVariable, vendor.email);

        Vendor.updateOne({ _id: vendor._id }, { $set: { otp } }).then();

        return res.status(200).send({ message: 'OTP Resent Successfully' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const verifyOTPAuthenticate = async (req: Request, res: Response) => {
    try {

        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: "Invalid Vendor id" });
        }

        const { error } = otpSchema.validate(req.body, { abortEarly: false });

        if (error) {
            return res.status(400).json({
                success: false,
                errors: error.details[0].message,
            });
        }

        const vendor = await Vendor.findOne({ _id: req.params.id }, { otp: 1 }).lean<IVendor | null>();

        if (!vendor || vendor.otp !== String(req.body.otp)) {
            return res.status(400).send({ errors: !vendor ? "Vendor not found" : "Invalid OTP" })
        }

        const token: string = uuidv4();

        Vendor.updateOne({ _id: vendor._id }, { $set: { token }, $unset: { otp: '' } }).then();

        return res.status(200).send({ data: token, message: 'OTP sent successfully to your email' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const resetPassword = async (req: Request, res: Response) => {
    try {

        const { error } = resetPasswordSchema.validate(req.body, { abortEarly: false });

        if (error) {
            return res.status(400).json({
                success: false,
                errors: error.details[0].message,
            });
        }

        const vendor = await Vendor.countDocuments({ token: req.params.token });

        if (!vendor) {
            return res.status(400).send({ errors: 'Invalid token' })
        }

        const { newPassword, confirmPassword } = req.body;

        if (newPassword !== confirmPassword) {
            return res.status(400).send({ errors: 'Password and confirm password does not match' })
        }

        Vendor.updateOne({ token: req.params.token }, { $set: { password: await hashPassword(newPassword), tokens: [] }, $unset: { token: '' } }).then();

        return res.status(200).send({ message: 'Password reset successfully' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const dashboard = async (req: Request, res: Response) => {
    try {

        const vendor = await Vendor.findOne({ _id: req.user?._id, isDeleted: false }).lean<IVendor | null>();

        return res.status(200).send({ data: vendor, message: `Welcome vendor ${vendor?.firstName} ${vendor?.lastName}` });
    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }
}

export const getProfile = async (req: Request, res: Response) => {
    try {

        const vendor = await Vendor.findOne({ _id: req.user?._id, isDeleted: false }).lean<IVendor | null>();

        return res.status(200).send({ data: vendor, message: 'Vendor profile successfully received' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }
}

export const changePassword = async (req: Request, res: Response) => {
    try {

        const { error } = changePasswordSchema.validate(req.body, { abortEarly: false });

        if (error) {
            return res.status(400).json({
                success: false,
                errors: error.details[0].message,
            });
        }
        const { oldPassword, newPassword, confirmPassword } = req.body

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: "New password and confirm password do not match." });
        }

        const vendor = await Vendor.findOne({ _id: req.user?._id, isDeleted: false }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(404).json({ message: "Vendor not found." });
        }

        const isMatch = await bcrypt.compare(oldPassword, vendor.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Old password is incorrect." });
        }

        Vendor.updateOne({ _id: req.user?._id }, { $set: { password: await hashPassword(newPassword), tokens: [] } }).then();

        return res.status(200).json({ message: "Password updated successfully." });

    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const updateProfile = async (req: Request, res: Response) => {
    try {

        const { firstName, lastName, email, phone, address, isPublic } = req.body;

        const [emailExists, phoneExists] = await Promise.all([
            Vendor.countDocuments({ email: emailFormatter(email), _id: { $ne: req.user?._id }, isDeleted: false }),
            Vendor.countDocuments({ phone: phoneFormatter(phone), _id: { $ne: req.user?._id }, isDeleted: false })
        ])

        if (emailExists || phoneExists) {
            return res.status(400).send({ message: emailExists ? "Email already exists." : "Phone already exists." });
        }

        let obj: any = {};

        obj = {
            shopName: req.body.shopName,
            firstName: capitalizeName(firstName),
            lastName: capitalizeName(lastName),
            email: emailFormatter(email),
            phone: phoneFormatter(phone),
            about: req?.body?.about,
            vatNumber: req?.body?.vatNumber,
            isPublic: isPublic,
            address: address
        }

        if (req.file) {

            obj = {
                ...obj,
                profile: req.file.filename
            }
        }

        Vendor.updateOne({ _id: req.user?._id }, { $set: obj }).then();

        return res.status(200).json({ message: "Profile updated successfully." });

    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const logout = async (req: Request, res: Response) => {
    try {

        if (!req.headers.authorization) {
            return res.status(401).json({ message: "Unauthorized: No token provided" });
        }

        const authToken = req.headers.authorization.split(" ")[1];

        if (!authToken) {
            return res.status(401).json({ message: "Unauthorized: Invalid token" });
        }

        const decoded = jwt.decode(authToken) as JwtPayload | null;

        if (!decoded || !decoded._id) {
            return res.status(400).json({ message: "Invalid token" });
        }

        Vendor.updateOne({ _id: decoded._id }, { $pull: { tokens: authToken } }).then();

        return res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};


