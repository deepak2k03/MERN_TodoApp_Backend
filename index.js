// index.js (safe, minimal)
import express from "express";
import { collectionName, connection } from "./dbconfig.js";
import cors from "cors";
import { ObjectId } from "mongodb";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// SAFE CORS + preflight
const allowedOrigins = [
  process.env.CLIENT_URL,
  "http://localhost:5173",
  "http://localhost:3000"
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS not allowed"));
  },
  credentials: true,
}));
app.options("/*", cors({
  origin: allowedOrigins,
  credentials: true
}));

// helper for cookie options
const cookieOpts = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "none",
  maxAge: 5 * 24 * 60 * 60 * 1000,
};

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const userData = req.body;
    if (!userData.email || !userData.password) {
      return res.status(400).send({ success: false, msg: "Please enter valid email and password" });
    }
    const db = await connection();
    const collection = await db.collection("users");
    const result = await collection.findOne({ email: userData.email, password: userData.password });
    if (!result) return res.status(404).send({ success: false, msg: "User Not Found" });

    const payload = { email: result.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET || "Google", { expiresIn: "5d" });

    res.cookie("token", token, cookieOpts);
    return res.send({ success: true, msg: "Logged In successfully", token });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).send({ success: false, msg: "Server error" });
  }
});

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const userData = req.body;
    if (!userData.email || !userData.password) {
      return res.status(400).send({ success: false, msg: "Please enter valid email and password" });
    }
    const db = await connection();
    const collection = await db.collection("users");
    const existing = await collection.findOne({ email: userData.email });
    if (existing) return res.status(409).send({ success: false, msg: "User already exists" });

    const result = await collection.insertOne(userData);
    if (!result.insertedId) return res.status(500).send({ success: false, msg: "Registration failed" });

    const payload = { email: userData.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET || "Google", { expiresIn: "5d" });

    res.cookie("token", token, cookieOpts);
    return res.send({ success: true, msg: "User registered successfully", token });
  } catch (err) {
    console.error("Signup error:", err.message);
    return res.status(500).send({ success: false, msg: "Server error" });
  }
});

// AUTH MIDDLEWARE
function verifyToken(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).send({ msg: "No token provided", success: false });
  jwt.verify(token, process.env.JWT_SECRET || "Google", (err, decoded) => {
    if (err) return res.status(401).send({ msg: "Invalid Token", success: false });
    req.user = decoded;
    next();
  });
}

// TASK ROUTES (same as yours)
app.post("/add-task", verifyToken, async (req, res) => {
  try {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.insertOne(req.body);
    if (result.insertedId) return res.send({ message: "task added", success: true, result });
    return res.status(500).send({ message: "task not added", success: false });
  } catch (err) {
    console.error("add-task error:", err.message);
    return res.status(500).send({ message: err.message, success: false });
  }
});

app.get("/tasks", verifyToken, async (req, res) => {
  try {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.find().toArray();
    return res.send({ message: "task list fetched", success: true, result });
  } catch (err) {
    console.error("tasks error:", err.message);
    return res.status(500).send({ message: "Error Try after some time", success: false });
  }
});

app.put("/update-task", verifyToken, async (req, res) => {
  try {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const { _id, ...fields } = req.body;
    if (!_id) return res.status(400).send({ message: "_id is required", success: false });
    const update = { $set: fields };
    const result = await collection.updateOne({ _id: new ObjectId(_id) }, update);
    return res.send({ message: "task updated", success: true, result });
  } catch (err) {
    console.error("update-task error:", err.message);
    return res.status(500).send({ message: "Error Try after some time", success: false });
  }
});

app.get("/task/:id", verifyToken, async (req, res) => {
  try {
    const db = await connection();
    const id = req.params.id;
    const collection = await db.collection(collectionName);
    const result = await collection.findOne({ _id: new ObjectId(id) });
    if (!result) return res.status(404).send({ message: "Task not found", success: false });
    return res.send({ message: "task fetched", success: true, result });
  } catch (err) {
    console.error("task/:id error:", err.message);
    return res.status(500).send({ message: "Error Try after some time", success: false });
  }
});

app.delete("/delete/:id", verifyToken, async (req, res) => {
  try {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount && result.deletedCount > 0) return res.send({ message: "task deleted", success: true, result });
    return res.status(404).send({ message: "Task not found", success: false });
  } catch (err) {
    console.error("delete error:", err.message);
    return res.status(500).send({ message: "Error Try after some time", success: false });
  }
});

app.delete("/delete-multiple", verifyToken, async (req, res) => {
  try {
    const ids = req.body;
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).send({ message: "No ids provided", success: false });
    const db = await connection();
    const collection = await db.collection(collectionName);
    const objectIds = ids.map((id) => new ObjectId(id));
    const result = await collection.deleteMany({ _id: { $in: objectIds } });
    if (result.deletedCount && result.deletedCount > 0) return res.send({ message: "tasks deleted", success: true, result });
    return res.send({ message: "No tasks deleted", success: false, result });
  } catch (err) {
    console.error("delete-multiple error:", err.message);
    return res.status(500).send({ message: err.message, success: false });
  }
});

// optional logout
app.post("/logout", (req, res) => {
  res.clearCookie("token", { sameSite: "none", secure: process.env.NODE_ENV === "production" });
  return res.send({ success: true, msg: "Logged out" });
});

const PORT = process.env.PORT || 3200;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
