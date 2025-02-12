import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import { createClient } from "redis";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

const app = express();
app.use(express.json());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "Too many requests from this IP, please try again later.",
});
app.use(limiter);

mongoose.connect(process.env.MONGO_URI!)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, default:"guest" },
});
const User = mongoose.model("User", UserSchema);

const redisClient = createClient({
    socket: {
        host: process.env.REDIS_HOST,
        port: Number(process.env.REDIS_PORT),
    },
});
redisClient.connect()
    .then(() => console.log("Redis connected"))
    .catch(err => {
        console.error("Redis connection error:", err.message);
        process.exit(1); // Exit process if connection fails
});

app.post("/auth/sign-up", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({ username, password: hashedPassword });
    return res.status(201).json({ message: "User created successfully", user: newUser });
});

app.post("/auth/sign-in", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    const user = await User.findOne({ username }).lean().explain();

    if (!user || !(await bcrypt.compare(password, user.password)))
        return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET!, { expiresIn: "1h" });

    // Store session in Redis
    const sessionId = crypto.randomUUID();
    await redisClient.setEx(`session:${user._id}`, 3600, sessionId); 

    return res.status(200).json({ message: "Login successful", token });
});

app.post("/auth/sign-out", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET!);
        const userId = decoded.userId;
        await redisClient.del(`session:${userId}`);
        return res.status(200).json({ message: "Logout successful" });
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
});

app.listen(3000, () => console.log("Server running on port 3000"));