// index.js (safe, defensive preflight)
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

// SAFE CORS
const allowedOrigins = [
  process.env.CLIENT_URL, // set this on Render to your Vercel URL
  "http://localhost:5173",
  "http://localhost:3000",
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // allow non-browser requests (no origin)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS not allowed"));
  },
  credentials: true,
}));

// --- DEFENSIVE PRE-FLIGHT HANDLER (logs errors, never throws) ---
app.use((req, res, next) => {
  try {
    const origin = req.headers.origin;

    if (!origin) {
      // non-browser clients (curl/Postman) — allow
      res.header("Access-Control-Allow-Origin", "*");
    } else if (allowedOrigins.includes(origin)) {
      // allowed browser origin
      res.header("Access-Control-Allow-Origin", origin);
      res.header("Access-Control-Allow-Credentials", "true");
    } else {
      // not allowed origin — set a safe header; don't throw
      res.header("Access-Control-Allow-Origin", "null");
    }

    // Common CORS headers
    res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  } catch (err) {
    // log full error so Render shows it and return safe 500 JSON
    console.error("Preflight middleware error:", err && err.stack ? err.stack : err);
    return res.status(500).send({ success: false, msg: "Server error (CORS)" });
  }
});
// --- END PRE-FLIGHT HANDLER ---

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
    console.error("Login error:", err && err.stack ? err.stack : err);
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
    console.error("Signup error:", err && err.stack ? err.stack : err);
    return res.status(500).send({ success: false, msg: "Server error" });
  }
});

// AUTH MIDDLEWARE
function verifyToken(req, res, next) {
  // try cookie first
  let token = req.cookies && req.cookies.token;

  // fallback: Authorization header "Bearer <token>"
  if (!token && req.headers && req.headers.authorization) {
    const parts = req.headers.authorization.split(" ");
    if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
      token = parts[1];
    }
  }

  if (!token) {
    return res.status(401).send({ msg: "No token provided", success: false });
  }

  jwt.verify(token, process.env.JWT_SECRET || "Google", (err, decoded) => {
    if (err) {
      // log error to help debugging
      console.error("JWT verify error:", err && err.message ? err.message : err);
      return res.status(401).send({ msg: "Invalid Token", success: false });
    }
    req.user = decoded;
    next();
  });
}


// TASK ROUTES
app.post("/add-task", verifyToken, async (req, res) => {
  try {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.insertOne(req.body);
    if (result.insertedId) return res.send({ message: "task added", success: true, result });
    return res.status(500).send({ message: "task not added", success: false });
  } catch (err) {
    console.error("add-task error:", err && err.stack ? err.stack : err);
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
    console.error("tasks error:", err && err.stack ? err.stack : err);
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
    console.error("update-task error:", err && err.stack ? err.stack : err);
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
    console.error("task/:id error:", err && err.stack ? err.stack : err);
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
    console.error("delete error:", err && err.stack ? err.stack : err);
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
    console.error("delete-multiple error:", err && err.stack ? err.stack : err);
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
