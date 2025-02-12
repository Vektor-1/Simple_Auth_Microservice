import "dotenv/config";
import express from "express";
import crypto from "crypto";
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
    createdAt: { type: Date, default: Date.now },
    apiKey: { type: String, unique: true, sparse: true },
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

const verifyToken = (roles = []) => {
    return async (req, res, next) => {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ error: "No token provided" });

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!);
            const user = await User.findById(decoded.userId).lean();
            if (!user) return res.status(401).json({ error: "User not found" });

            if (roles.length && !roles.includes(user.role))
                return res.status(403).json({ error: "Access denied" });

            req.user = user;
            next();
        } catch (err) {
            return res.status(401).json({ error: "Invalid token" });
        }
    };
};

const verifyApiKey = async (req, res, next) => {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey) return res.status(401).json({ error: "API key required" });

    const user = await User.findOne({ apiKey }).lean();
    if (!user) return res.status(401).json({ error: "Invalid API key" });

    req.user = user;
    next();
};

app.post("/auth/sign-up", verifyToken(["admin"]), async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) 
        return res.status(400).json({ error: "Username and password required" });

    // Ensure the role is valid
    const validRoles = ["admin", "user", "guest"];
    if (role && !validRoles.includes(role)) 
        return res.status(400).json({ error: "Invalid role" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({ 
        username, 
        password: hashedPassword, 
        role: role || "guest" // Default role is guest
    });

    return res.status(201).json({ message: "User created successfully", user: newUser });
});

app.post("/auth/generate-api-key", verifyToken(["admin"]), async (req, res) => {
    const apiKey = crypto.randomBytes(32).toString("hex");
    await User.findByIdAndUpdate(req.user._id, { apiKey });
    res.json({ message: "API key generated", apiKey });
});

app.get("/api/protected-data", verifyApiKey, (req, res) => {
    res.json({ message: "Access granted!", user: req.user });
});

app.post("/auth/sign-in", async (req, res) => {
    const { username, password } = req.body;
    const redisKey = `login_attempts:${username}`;

    // Check login attempts
    const attempts = await redisClient.get(redisKey);
    if (attempts && parseInt(attempts) >= 5)
        return res.status(429).json({ error: "Too many login attempts. Try again later." });

    const user = await User.findOne({ username }).lean();
    if (!user || !(await bcrypt.compare(password, user.password))) {
        await redisClient.incr(redisKey);
        await redisClient.expire(redisKey, 900); // Reset after 15 minutes
        return res.status(401).json({ error: "Invalid credentials" });
    }

    await redisClient.del(redisKey); // Reset attempts on success

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET!, { expiresIn: "1h" });
    await redisClient.setEx(`session:${user._id}`, 3600, token);

    res.status(200).json({ message: "Login successful", token });
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