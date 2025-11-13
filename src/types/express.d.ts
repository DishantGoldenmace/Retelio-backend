// src/types/express.d.ts
import { VendorDocument } from "../models/Vendor";
import { AdminDocument } from "../models/Admin"; // adjust path to your Vendor model
// adjust path to your Vendor model

declare global {
    namespace Express {
        export interface Request {
            user?: VendorDocument;
            user?: AdminDocument;
        }
    }
}
