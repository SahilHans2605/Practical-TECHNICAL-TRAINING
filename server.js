const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");

const SECRET = "q2-jwt-secret";
const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
  })
);

const Note = mongoose.model(
  "Note",
  new mongoose.Schema({
    userId: String,
    text: String,
    createdAt: { type: Date, default: Date.now },
  })
);

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
}

function sign(user) {
  return jwt.sign(
    { id: String(user._id), name: user.name, email: user.email },
    SECRET,
    { expiresIn: "1d" }
  );
}

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: "All fields are required" });
  if (await User.findOne({ email })) return res.status(400).json({ message: "Email already registered" });
  const user = await User.create({ name, email, password: await bcrypt.hash(password, 8) });
  res.json({ token: sign(user), user: { name, email } });
});

app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password || "", user.password))) {
    return res.status(401).json({ message: "Invalid email or password" });
  }
  res.json({ token: sign(user), user: { name: user.name, email: user.email } });
});

app.get("/api/dashboard", auth, async (req, res) => {
  const notes = await Note.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ user: { name: req.user.name, email: req.user.email }, notes });
});

app.post("/api/notes", auth, async (req, res) => {
  if (!req.body.text) return res.status(400).json({ message: "Text is required" });
  res.json(await Note.create({ userId: req.user.id, text: req.body.text }));
});

(async () => {
  const memory = await MongoMemoryServer.create();
  await mongoose.connect(process.env.MONGO_URI || memory.getUri());
  app.listen(3000, () => console.log("http://localhost:3000"));
})();
