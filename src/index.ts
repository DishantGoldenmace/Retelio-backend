import express, { Request, Response } from "express";
import userRoutes from "./routes/users";
import vendorRoutes from "./routes/vendor";
import adminRoutes from "./routes/admin";
import path from "path";
import dotenv from "dotenv";
import connectDB from "./config/dbConnection";
import { errorHandler } from "./middlewares/errorHandler";
import cors from "cors";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

connectDB();

app.use(express.json());

app.use(cors());

app.use("/uploads", express.static(path.join(__dirname, "..", "uploads")));

// Routes
app.use("/api/users", userRoutes);
app.use("/api/vendors", vendorRoutes);
app.use("/api/admin", adminRoutes);

app.use(errorHandler);

// Test route
app.get("/", (req: Request, res: Response) => {
    res.send("Hello Nodejs");
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
