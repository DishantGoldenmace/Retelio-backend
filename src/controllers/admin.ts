import { Request, response, Response } from 'express';
import mongoose from 'mongoose';
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import Admin, { IAdmin } from "../models/admin";
import Vendor, { IVendor } from "../models/vendor";
import { vendorLoginSchema } from '../validations/validations';



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

        const admin = await Admin.findOne({
            email: email.toLowerCase().trim(),
            isDeleted: false
        }).lean<IAdmin | null>();

        if (!admin) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }


        const token = jwt.sign(
            { _id: admin._id, email: admin.email },
            process.env.JWT_SECRET as string,
            { expiresIn: "7d" }
        );

        Admin.updateOne({
            _id: admin._id,
        }, {
            $push: {
                tokens: token,
            }
        }).then();

        return res.status(200).send({ data: token, message: 'Admin Login Successfully' });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }

}

export const dashboard = async (req: Request, res: Response) => {
    try {

        const vendor = await Admin.findOne({ _id: req.user?._id, isDeleted: false }).lean<IAdmin | null>();

        return res.status(200).send({ data: vendor, message: 'Vendor Dashboard' });
    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }
}

export const listVendors = async (req: Request, res: Response) => {
    try {

        if (!['pending', 'approved', 'rejected', 'all'].includes(req.params.status)) {
            return res.status(400).send({ message: 'Invalid status' });
        }

        let obj: any = {};

        let condition: any = {};

        obj = {
            'pending': 'pending',
            'approved': 'approved',
            'rejected': 'rejected'
        }

        if (req.params.status !== 'all') {
            condition = { isDeleted: false, isVerified: true, status: obj[req.params.status] }
        } else {
            condition = { isDeleted: false, isVerified: true }
        }

        const vendor = await Vendor.find(condition).lean<IVendor[]>();

        return res.status(200).send({ data: vendor, message: vendor.length ? 'Vendors List Successfully Received' : 'No vendors found' });
    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }
}

export const updateVendorStatus = async (req: Request, res: Response) => {
    try {

        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: "Invalid Vendor id" });
        }

        if (!['approved', 'rejected'].includes(req.body.status)) {
            return res.status(400).send({ message: 'Invalid status' });
        }

        const vendor = await Vendor.findOne({
            _id: req.params.id,
            isDeleted: false
        }).lean<IVendor | null>();

        if (!vendor) {
            return res.status(400).send({ message: 'Vendor not found' });
        }

        Vendor.updateOne({ _id: req.params.id }, {
            $set: {
                status: req.body.status
            }
        }).then()

        return res.status(200).send({ message: `Vendor status ${req.body.status} updated successfully.` });

    } catch (error) {
        return res.status(500).send({ message: 'Internal Server Error' });
    }
}



