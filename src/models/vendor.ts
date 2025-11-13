import mongoose, { Schema, Document } from 'mongoose';

export interface IVendor extends Document {
    address: object;
    age: number;
    status: string;
    isVerified: boolean;
    isEmailVerified: boolean;
    isPhoneVerified: boolean;
    isPublic: boolean
    isDeleted: boolean;
    dob: Date;
    email: string;
    firstName: string;
    lastName: string;
    password: string;
    phone: string;
    pivaCode: string;
    referralCode: string;
    shopName: string;
    otp: String,
    token: string;
    profile: string;
    about: string;
    vatNumber: string;
    tokens: string[];
}

const VendorSchema: Schema = new Schema(
    {
        address: { type: Object },
        age: { type: Number },
        dob: { type: Date },
        status: { type: String, default: 'pending' },
        email: { type: String },
        firstName: { type: String },
        lastName: { type: String },
        password: { type: String },
        phone: { type: String },
        pivaCode: { type: String },
        referralCode: { type: String },
        shopName: { type: String },
        otp: { type: String },
        token: { type: String },
        profile: { type: String },
        vatNumber: { type: String },
        about: { type: String },
        isVerified: { type: Boolean, default: false },
        isEmailVerified: { type: Boolean, default: false },
        isPhoneVerified: { type: Boolean, default: false },
        isPublic: { type: Boolean, default: false },
        isDeleted: { type: Boolean, default: false },
        tokens: { type: [String], default: [] }
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IVendor>("Vendor", VendorSchema);