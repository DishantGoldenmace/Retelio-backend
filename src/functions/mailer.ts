import nodemailer from "nodemailer";
import MailTemplate, { IMailTemplate } from "../models/templates";

export interface MailVariables {
    [key: string]: string;
}

export const sendMail = async (
    templateName: string,
    mailVariable: MailVariables,
    email: string
): Promise<{ type: string; message: string }> => {
    try {

        const template = await MailTemplate.findOne({
            templateEvent: templateName,
            isDeleted: false,
            active: true,
        }).lean<IMailTemplate | null>();

        if (!template) {
            throw new Error("Mail template not found");
        }

        let subject = template.subject || "";
        let html = template.htmlBody || "";
        let text = template.textBody || "";

        for (const key in mailVariable) {
            if (Object.prototype.hasOwnProperty.call(mailVariable, key)) {
                const value = mailVariable[key];
                if (typeof value === "string") {
                    subject = subject.split(key).join(value);
                    html = html.split(key).join(value);
                    text = text.split(key).join(value);
                }
            }
        }

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: 'wd47.stpl@gmail.com',
                pass: 'pntb jpda whbf hurf ',
            },
        });

        const mailOptions = {
            from: "wd47.stpl@gmail.com",
            to: email,
            subject,
            text,
            html,
        };

        await new Promise<void>((resolve, reject) => {
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) return reject(error);
                resolve();
            });
        });

        return { type: "success", message: "Mail successfully sent" };
    } catch (error: any) {
        throw new Error(error.message || "Failed to send mail");
    }
};
