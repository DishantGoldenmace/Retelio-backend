import dotenv from "dotenv";
dotenv.config();

import twilio, { Twilio } from "twilio";

const accountSid = process.env.TWILIO_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const fromPhone = process.env.TWILIO_PHONE_NUMBER;

if (!accountSid || !authToken || !fromPhone) {
    throw new Error(
        "Twilio credentials are missing! Check TWILIO_SID, TWILIO_AUTH_TOKEN, and TWILIO_PHONE_NUMBER in your .env"
    );
}

const client: Twilio = twilio(accountSid, authToken);

interface User {
    phone: string;
    OTP?: number;
}

export const sendTwilioMessage = async (
    user: User
): Promise<{ type: string; message: string }> => {
    try {
        const body = `Your Stockmate Phone verification code is ${user.OTP}`;
        const message = await client.messages.create({
            body,
            from: fromPhone,
            to: user.phone,
        });

        console.log("Message sent successfully with SID:", message.sid);

        return { type: "success", message: "OTP successfully sent" };
    } catch (error: any) {
        console.error("Twilio error:", error.message || error);
        throw error;
    }
};
