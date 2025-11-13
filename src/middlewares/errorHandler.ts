import { Request, Response, NextFunction } from "express";

export const errorHandler = (
    err: any,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    console.error(err);

    // Multer file type error
    if (err instanceof Error && err.message.includes("Only images")) {
        return res.status(400).json({ message: err.message });
    }

    // Multer file size limit
    if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ message: "File too large" });
    }

    res.status(500).json({ message: "Internal Server Error" });
};
