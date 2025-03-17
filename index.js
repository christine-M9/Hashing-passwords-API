import express from "express";
import bcrypt from "bcryptjs";
import fs from "fs/promises";
import path from "path";
import cors from "cors";
import { fileURLToPath } from "url";

// directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const USERS_FILE = path.join(__dirname, "users.json");

// Middleware
app.use(express.json());
app.use(cors());

// function to read users file
async function readUsersFile() {
  try {
    await fs.access(USERS_FILE).catch(async () => {
      // Creating file if it doesn't exist
      await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2), "utf8");
    });

    const data = await fs.readFile(USERS_FILE, "utf8");
    return data.trim() ? JSON.parse(data) : [];
  } catch (error) {
    console.error("Error reading users file:", error);
    return [];
  }
}

// function to write to users file
async function writeUsersFile(users) {
  try {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
  } catch (error) {
    console.error("Error writing users file:", error);
    throw new Error("Failed to write users file");
  }
}

// Testing route to verify JSON parsing
app.post("/test", (req, res) => {
  console.log("Test request body:", req.body);
  res.json({ received: req.body });
});

// Signup endpoint
app.post("/api/auth/signup", async (req, res) => {
  try {
    console.log("Signup request body:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    // Read existing users
    const users = await readUsersFile();

    // Check if user already exists
    if (users.some((user) => user.email === email)) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Add new user
    users.push({
      id: Date.now().toString(),
      email,
      password: hashedPassword,
    });

    // Save updated users
    await writeUsersFile(users);

    res.status(200).json({ message: "success" });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Signin endpoint
app.post("/api/auth/signin", async (req, res) => {
  try {
    console.log("Signin request body:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    // Read users
    const users = await readUsersFile();

    // Find user
    const user = users.find((user) => user.email === email);

    if (!user) {
      return res.status(200).json({ isAuthenticated: false });
    }

    // Comparing passwords
    const isMatch = await bcrypt.compare(password, user.password);

    res.status(200).json({ isAuthenticated: isMatch });
  } catch (error) {
    console.error("Signin error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Log any unhandled promise rejections
// process.on("unhandledRejection", (reason, promise) => {
//   console.error("Unhandled Rejection at:", promise, "reason:", reason);
// });
