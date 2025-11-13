import mongoose, { Schema, Document } from 'mongoose';

export interface IAdmin extends Document {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    access: string;
    roles: string;
    phone: string;
    dob: Date;
    isDeleted: boolean;
    otp: String,
    tokens: string[];
}

const AdminSchema: Schema = new Schema({
    firstName: { type: String },
    lastName: { type: String },
    email: { type: String },
    password: { type: String },
    access: { type: String },
    roles: { type: String },
    phone: { type: String },
    dob: { type: Date },
    isDeleted: { type: Boolean, default: false },
    otp: { type: String },
    tokens: { type: [String], default: [] }
}, {
    timestamps: true
});

export default mongoose.model<IAdmin>('Admin', AdminSchema);