import mongoose, { Schema, Document, Types } from "mongoose";

export interface IMailTemplate extends Document {
    templateEvent: string;
    active: boolean;
    subject: string;
    mailVariables: string;
    htmlBody: string;
    textBody: string;
    isDeleted: boolean;
    createdBy?: Types.ObjectId;
    updatedBy?: Types.ObjectId;
    createdAt: Date;
    updatedAt: Date;
}

const MailTemplateSchema: Schema = new Schema(
    {
        templateEvent: {
            type: String,
            required: true
        },
        active: {
            type: Boolean,
            default: true
        },
        subject: {
            type: String,
        },
        mailVariables: {
            type: String,
        },
        htmlBody: {
            type: String,
        },
        textBody: {
            type: String,
        },
        isDeleted: {
            type: Boolean,
            default: false,
        },
        createdBy: {
            type: Schema.Types.ObjectId
        },
        updatedBy: {
            type: Schema.Types.ObjectId
        },
    },
    {
        timestamps: true,
    }
);

// 3️⃣ Export model
export default mongoose.model<IMailTemplate>("MailTemplate", MailTemplateSchema);
