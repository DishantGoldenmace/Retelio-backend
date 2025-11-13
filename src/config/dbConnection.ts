import mongoose from 'mongoose';
import moment from 'moment';
import Admin from '../models/admin';
import MailTemplate from '../models/templates';
import { hashPassword } from '../functions/common';

const connectDB = async () => {

    const mongoUri = process.env.DATABASE_URI || 'mongodb://localhost:27017/mydb';

    try {
        const connect = await mongoose.connect(mongoUri);

        console.log(
            "Database connected: ",
            connect.connection.host,
            connect.connection.name
        );

        const [checkAdmin, template] = await Promise.all([
            Admin.countDocuments({ isDeleted: false }),
            MailTemplate.countDocuments({ isDeleted: false })
        ]);

        if (!checkAdmin) {
            await Admin.create({
                firstName: 'Stockmate',
                lastName: 'Enterprise',
                email: "stockmateenterprise@gmail.com",
                password: await hashPassword("Admin@11"),
                access: 'owner',
                roles: 'superAdmin',
                phone: "+911234567890",
                dob: moment(new Date("01/01/1998")).format("YYYY-MM-DD[T00:00:00.000Z]")
            });
        }

        if (!template) {
            await MailTemplate.insertMany([{
                templateEvent: 'vendor-verify',
                subject: 'Vendor Verification',
                mailVariables: '%firstName% %lastName% %link%',
                htmlBody: `Hello %firstName% %lastName%,<br><br>Your Verification Link is <br><a href=%link%>Click Here</a>`,
                textBody: `Hello %firstName% %lastName%,<br><br>Your Verification Link is <br><a href=%link%>Click Here</a>`
            },
            {
                templateEvent: 'vendor-forgot-password',
                subject: 'Vendor Password Reset',
                mailVariables: '%firstName% %lastName% %otp%',
                htmlBody: `Hello %firstName% %lastName%,<br><br>Your OTP for password reset is: <b>%otp%</b><br>Please use this OTP to reset your password.`,
                textBody: `Hello %firstName% %lastName%,\n\nYour OTP for password reset is: %otp%\nPlease use this OTP to reset your password.`
            },
            {
                templateEvent: 'vendor-resent-otp',
                subject: 'Resend OTP',
                mailVariables: '%firstName% %lastName% %otp%',
                htmlBody: `Hello %firstName% %lastName%,<br><br>Your Resent OTP for password reset is: <b>%otp%</b><br>Please use this Resent OTP to reset your password.`,
                textBody: `Hello %firstName% %lastName%,\n\nYour Resent OTP for password reset is: %otp%\nPlease use this Resent OTP to reset your password.`
            }
            ])
        }

    } catch (error) {
        console.error('MongoDB connection failed:', error);
        process.exit(1); // Exit process with failure
    }
};

export default connectDB;
