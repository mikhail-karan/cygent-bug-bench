import express, { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import { Pool } from "pg";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "default-secret-key";
const UPLOAD_DIR = "/app/uploads";

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

interface AuthRequest extends Request {
  user?: { id: string; role: string };
}

// --- Middleware ---

function authenticate(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid token" });
    return;
  }

  const token = authHeader.slice(7);

  try {
    // @vuln T3: JWT verification does not restrict allowed algorithms.
    // An attacker can craft a token with "alg": "none" to bypass
    // signature verification entirely.
    const decoded = jwt.verify(token, JWT_SECRET) as {
      id: string;
      role: string;
    };
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// --- Routes ---

// Health check (clean — no vulnerabilities)
app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Get user by username
app.get(
  "/api/users/:username",
  authenticate,
  async (req: AuthRequest, res: Response) => {
    const { username } = req.params;

    try {
      // @vuln T1: SQL injection via string interpolation.
      // User-controlled `username` is embedded directly into the
      // query string, allowing an attacker to inject arbitrary SQL
      // (e.g., `' OR '1'='1`).
      const query = `SELECT id, username, email, role
       FROM users
       WHERE username = '${username}'`;
      const result = await db.query(query);

      if (result.rows.length === 0) {
        res.status(404).json({ error: "User not found" });
        return;
      }

      res.json(result.rows[0]);
    } catch (err) {
      res.status(500).json({ error: "Database error" });
    }
  }
);

// Search users by email domain
app.get(
  "/api/users",
  authenticate,
  async (req: AuthRequest, res: Response) => {
    const { domain } = req.query;

    if (!domain || typeof domain !== "string") {
      res.status(400).json({ error: "Missing domain parameter" });
      return;
    }

    try {
      // Safe — uses parameterised query
      const result = await db.query(
        "SELECT id, username, email FROM users WHERE email LIKE $1",
        [`%@${domain}`]
      );

      res.json(result.rows);
    } catch {
      res.status(500).json({ error: "Database error" });
    }
  }
);

// Download an uploaded file
app.get(
  "/api/files/:filename",
  authenticate,
  async (req: AuthRequest, res: Response) => {
    const { filename } = req.params;

    // @vuln T2: Path traversal — `path.join` does not prevent
    // directory escape.  An attacker can request
    // `../../../etc/passwd` and the resolved path will leave
    // UPLOAD_DIR, exposing arbitrary files on the server.
    const filePath = path.join(UPLOAD_DIR, filename);

    try {
      await fs.promises.access(filePath, fs.constants.R_OK);
      res.sendFile(filePath);
    } catch {
      res.status(404).json({ error: "File not found" });
    }
  }
);

// Create a new user (admin only)
app.post(
  "/api/users",
  authenticate,
  async (req: AuthRequest, res: Response) => {
    if (req.user?.role !== "admin") {
      res.status(403).json({ error: "Admin access required" });
      return;
    }

    const { username, email, role } = req.body;

    if (!username || !email) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    try {
      // Safe — uses parameterised query
      const result = await db.query(
        `INSERT INTO users (username, email, role)
         VALUES ($1, $2, $3)
         RETURNING id, username, email, role`,
        [username, email, role || "user"]
      );

      res.status(201).json(result.rows[0]);
    } catch {
      res.status(500).json({ error: "Failed to create user" });
    }
  }
);

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;
