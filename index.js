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

// ---- SAFE CORS FIX ----
const allowedOrigins = [
  process.env.CLIENT_URL,           // your Vercel app URL
  "http://localhost:5173",
  "http://localhost:3000"
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS: Not allowed by policy"));
  },
  credentials: true,
}));

// handle preflight requests
app.options("*", cors({
  origin: allowedOrigins,
  credentials: true,
}));
// ---- END CORS FIX ----


app.use(cookieParser());

app.post("/login", async (req, res) => {
  const userData = req.body;
  if (userData.email && userData.password) {
    const db = await connection();
    const collection = await db.collection("users");
    const result = await collection.findOne({
      email: userData.email,
      password: userData.password,
    });
    if (result) {
      jwt.sign(
        userData,
        process.env.JWT_SECRET || "Google",
        { expiresIn: "5d" },
        (err, token) => {
          res.send({
            success: true,
            msg: "Logged In successfully",
            token,
          });
        }
      );
    } else {
      res.send({
        success: false,
        msg: "User Not Found",
      });
    }
  } else {
    res.send({ success: false, msg: "Please enter valid email and password" });
  }
});

app.post("/signup", async (req, res) => {
  const userData = req.body;
  if (userData.email && userData.password) {
    const db = await connection();
    const collection = await db.collection("users");
    const result = await collection.insertOne(userData);
    if (result) {
      jwt.sign(
        userData,
        process.env.JWT_SECRET || "Google",
        { expiresIn: "5d" },
        (err, token) => {
          res.send({
            success: true,
            msg: "User registered successfully",
            token,
          });
        }
      );
    }
  } else {
    res.send({ success: false, msg: "Please enter valid email and password" });
  }
});

app.post("/add-task", verifyToken, async (req, res) => {
  const db = await connection();
  const collection = await db.collection(collectionName);
  const result = await collection.insertOne(req.body);
  if (result) {
    res.send({ message: "task added", success: true, result });
  } else {
    res.send({ message: "task added", success: false, result });
  }
});

app.get("/tasks", verifyToken, async (req, res) => {
  const db = await connection();
  const collection = await db.collection(collectionName);
  const result = await collection.find().toArray();
  if (result) {
    res.send({ message: "task list fetched", success: true, result });
  } else {
    res.send({ message: "Error Try after some time", success: false, result });
  }
});

app.put("/update-task", verifyToken, async (req, res) => {
  const db = await connection();
  const collection = await db.collection(collectionName);
  const { _id, ...fields } = req.body;
  const update = { $set: fields };
  const result = await collection.updateOne({ _id: new ObjectId(_id) }, update);
  if (result) {
    res.send({ message: "task updated", success: true, result });
  } else {
    res.send({ message: "Error Try after some time", success: false, result });
  }
});

app.get("/task/:id", verifyToken, async (req, res) => {
  const db = await connection();
  const id = req.params.id;
  const collection = await db.collection(collectionName);
  const result = await collection.findOne({ _id: new ObjectId(id) });
  if (result) {
    res.send({ message: "task fetched", success: true, result });
  } else {
    res.send({ message: "Error Try after some time", success: false, result });
  }
});

app.delete("/delete/:id", verifyToken, async (req, res) => {
  const db = await connection();
  const collection = await db.collection(collectionName);
  const result = await collection.deleteOne({
    _id: new ObjectId(req.params.id),
  });
  if (result) {
    res.send({ message: "task deleted", success: true, result });
  } else {
    res.send({ message: "Error Try after some time", success: false, result });
  }
});

// delete multiple tasks by array of ids in request body
app.delete("/delete-multiple", verifyToken, async (req, res) => {
  try {
    const ids = req.body; // expecting an array of id strings
    if (!Array.isArray(ids) || ids.length === 0) {
      return res
        .status(400)
        .send({ message: "No ids provided", success: false });
    }

    const db = await connection();
    const collection = await db.collection(collectionName);

    const objectIds = ids.map((id) => new ObjectId(id));
    const result = await collection.deleteMany({ _id: { $in: objectIds } });

    if (result.deletedCount && result.deletedCount > 0) {
      return res.send({ message: "tasks deleted", success: true, result });
    }

    return res.send({ message: "No tasks deleted", success: false, result });
  } catch (err) {
    console.error(err);
    return res.status(500).send({ message: err.message, success: false });
  }
});

function verifyToken(req, res, next) {
  const token = req.cookies["token"];
  jwt.verify(token, process.env.JWT_SECRET || "Google", (err, decoded) => {
    if (err) {
      return res.send({
        msg: "Invalid Token",
        success: false,
      });
    }
    next();
  });
}

const PORT = process.env.PORT || 3200;
app.listen(PORT);
