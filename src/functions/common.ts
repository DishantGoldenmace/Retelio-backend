import bcrypt from "bcrypt";

export async function hashPassword(plainPassword: string): Promise<string> {
    const saltRounds = 10;
    return await bcrypt.hash(plainPassword, saltRounds);
}

export function capitalizeName(name: string = ""): string {
    return name
        .toLowerCase()
        .replace(/(^\w)|(\s\w)/g, (match) => match.toUpperCase())
        .trim();
}

export function emailFormatter(email: string = ""): string {
    return email.toLowerCase().trim();
}

export function phoneFormatter(phone: string = ""): string {
    return phone.replace(/[- )(]/g, "").trim();
}

export const generateOTP = (): number => {
    return Math.floor(100000 + Math.random() * 900000);
};