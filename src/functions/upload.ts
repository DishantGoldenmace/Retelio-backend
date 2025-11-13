import multer, { FileFilterCallback } from "multer";
import path from "path";
import { Request } from "express";

// --- Storage configuration ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {

        let obj: any = {};

        obj = {
            'vendorImage': 'uploads/vendor',
            'productImage': 'uploads/product',
        }

        cb(null, obj[file.fieldname]);
    },
    filename: (req: Request, file, cb) => {

        const userId = req.user._id.toString();
        const ext = path.extname(file.originalname);
        cb(null, `${userId}${ext}`);
    },
});

const fileFilter = (req: Request, file: Express.Multer.File, cb: FileFilterCallback) => {

    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
        cb(null, true);
    } else {
        cb(new Error("Only images are allowed"));
    }
};

const limits = {
    fileSize: 5 * 1024 * 1024
};

export const upload = multer({
    storage,
    fileFilter,
    limits,
});
