const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "./schoolpro.sqlite";

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'eleve',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  subject TEXT NOT NULL,
  grade TEXT NOT NULL,
  content TEXT NOT NULL,
  author_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// Création du compte créateur avec des variables privées Render
if (process.env.CREATOR_EMAIL && process.env.CREATOR_PASSWORD) {
  const email = process.env.CREATOR_EMAIL.toLowerCase();
  const existing = db.prepare(
    "SELECT id FROM users WHERE email = ?"
  ).get(email);

  if (!existing) {
    const hash = bcrypt.hashSync(
      process.env.CREATOR_PASSWORD,
      12
    );

    db.prepare(`
      INSERT INTO users (name, email, password_hash, role)
      VALUES (?, ?, ?, 'createur')
    `).run("Créateur", email, hash);
  }
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.use("/api/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30
}));

app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Connexion requise."
    });
  }
  next();
}

function requireCreator(req, res, next) {
  if (req.session.user?.role !== "createur") {
    return res.status(403).json({
      error: "Accès réservé au créateur."
    });
  }
  next();
}

// INSCRIPTION ÉLÈVE
app.post("/api/auth/register", (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || !email || !password ||
      String(password).length < 8) {
    return res.status(400).json({
      error: "Nom, e-mail et mot de passe de 8 caractères minimum requis."
    });
  }

  try {
    const hash = bcrypt.hashSync(String(password), 12);

    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash, role)
      VALUES (?, ?, ?, 'eleve')
    `).run(
      String(name).trim(),
      String(email).trim().toLowerCase(),
      hash
    );

    const user = {
      id: result.lastInsertRowid,
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      role: "eleve"
    };

    req.session.user = user;
    res.json({ user });
  } catch {
    res.status(409).json({
      error: "Cette adresse e-mail est déjà utilisée."
    });
  }
});

// CONNEXION
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body || {};

  const user = db.prepare(
    "SELECT * FROM users WHERE email = ?"
  ).get(String(email || "").trim().toLowerCase());

  if (!user ||
      !bcrypt.compareSync(String(password || ""), user.password_hash)) {
    return res.status(401).json({
      error: "E-mail ou mot de passe incorrect."
    });
  }

  req.session.user = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };

  res.json({ user: req.session.user });
});

// UTILISATEUR CONNECTÉ
app.get("/api/auth/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// DÉCONNEXION
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// AFFICHER LES LEÇONS
app.get("/api/lessons", (req, res) => {
  const lessons = db.prepare(`
    SELECT id, title, subject, grade, content, created_at
    FROM lessons
    ORDER BY id DESC
  `).all();

  res.json(lessons);
});

// PUBLIER UNE LEÇON
app.post("/api/lessons", requireAuth, (req, res) => {
  if (!["professeur", "createur"].includes(req.session.user.role)) {
    return res.status(403).json({
      error: "Seuls les professeurs peuvent publier."
    });
  }

  const { title, subject, grade, content } = req.body || {};

  if (!title || !subject || !grade || !content) {
    return res.status(400).json({
      error: "Tous les champs sont obligatoires."
    });
  }

  const result = db.prepare(`
    INSERT INTO lessons
    (title, subject, grade, content, author_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    title,
    subject,
    grade,
    content,
    req.session.user.id
  );

  res.json({ id: result.lastInsertRowid });
});

// LISTE DES UTILISATEURS — CRÉATEUR
app.get(
  "/api/creator/users",
  requireAuth,
  requireCreator,
  (req, res) => {
    const users = db.prepare(`
      SELECT id, name, email, role, created_at
      FROM users
      ORDER BY id DESC
    `).all();

    res.json(users);
  }
);

// CRÉER UN PROFESSEUR — CRÉATEUR
app.post(
  "/api/creator/teachers",
  requireAuth,
  requireCreator,
  (req, res) => {
    const { name, email, password } = req.body || {};

    if (!name || !email || !password ||
        String(password).length < 8) {
      return res.status(400).json({
        error: "Informations invalides. Mot de passe de 8 caractères minimum."
      });
    }

    try {
      const hash = bcrypt.hashSync(password, 12);

      db.prepare(`
        INSERT INTO users
        (name, email, password_hash, role)
        VALUES (?, ?, ?, 'professeur')
      `).run(
        name.trim(),
        email.trim().toLowerCase(),
        hash
      );

      res.json({ ok: true });
    } catch {
      res.status(409).json({
        error: "Cet e-mail existe déjà."
      });
    }
  }
);

// PAGE PRINCIPALE
app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.listen(PORT, () => {
  console.log(`SchoolPro lancé sur le port ${PORT}`);
});
