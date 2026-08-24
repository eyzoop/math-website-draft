import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import OpenAI from "openai";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

const db = new Database(
  process.env.DB_PATH || path.join(__dirname, "app.db")
);

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT UNIQUE COLLATE NOCASE,
    password_hash TEXT,
    google_id TEXT UNIQUE,
    google_email TEXT,
    avatar_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS contest_logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS community_posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    date TEXT NOT NULL,
    likes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
  );
`);

/*
|--------------------------------------------------------------------------
| EXPRESS
|--------------------------------------------------------------------------
*/

const app = express();

app.set("trust proxy", 1);

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: false
  })
);

/*
|--------------------------------------------------------------------------
| SESSIONS
|--------------------------------------------------------------------------
*/

const SQLiteStore = SQLiteStoreFactory(session);

app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.db",
      dir: __dirname
    }),

    secret:
      process.env.SESSION_SECRET ||
      crypto.randomBytes(32).toString("hex"),

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

/*
|--------------------------------------------------------------------------
| PASSPORT
|--------------------------------------------------------------------------
*/

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(id);

  done(null, user || false);
});

/*
|--------------------------------------------------------------------------
| GOOGLE LOGIN
|--------------------------------------------------------------------------
*/

const googleConfigured = Boolean(
  process.env.GOOGLE_CLIENT_ID &&
  process.env.GOOGLE_CLIENT_SECRET
);

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,

        clientSecret:
          process.env.GOOGLE_CLIENT_SECRET,

        callbackURL:
          process.env.GOOGLE_CALLBACK_URL ||
          "http://localhost:3000/auth/google/callback"
      },

      (accessToken, refreshToken, profile, done) => {
        try {
          const googleId = profile.id;

          const email =
            profile.emails?.[0]?.value?.toLowerCase() ||
            null;

          const avatar =
            profile.photos?.[0]?.value ||
            null;

          /*
           * Check whether this Google account already exists.
           */

          let user = db
            .prepare(
              "SELECT * FROM users WHERE google_id = ?"
            )
            .get(googleId);

          if (user) {
            db.prepare(`
              UPDATE users
              SET google_email = ?,
                  avatar_url = ?
              WHERE id = ?
            `).run(
              email,
              avatar,
              user.id
            );

            return done(
              null,
              db
                .prepare(
                  "SELECT * FROM users WHERE id = ?"
                )
                .get(user.id)
            );
          }

          /*
           * If the Google email matches an existing
           * account, connect Google to that account.
           */

          if (email) {
            user = db
              .prepare(
                "SELECT * FROM users WHERE email = ?"
              )
              .get(email);

            if (user) {
              db.prepare(`
                UPDATE users
                SET google_id = ?,
                    google_email = ?,
                    avatar_url = ?
                WHERE id = ?
              `).run(
                googleId,
                email,
                avatar,
                user.id
              );

              return done(
                null,
                db
                  .prepare(
                    "SELECT * FROM users WHERE id = ?"
                  )
                  .get(user.id)
              );
            }
          }

          /*
           * Create a new account.
           */

          let base =
            (profile.displayName || "math-user")
              .replace(/[^a-zA-Z0-9_]/g, "")
              .slice(0, 24);

          if (!base) {
            base = "math-user";
          }

          let username = base;
          let number = 1;

          while (
            db
              .prepare(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE"
              )
              .get(username)
          ) {
            username = `${base}${number++}`;
          }

          const result = db
            .prepare(`
              INSERT INTO users (
                username,
                email,
                google_id,
                google_email,
                avatar_url
              )

              VALUES (?, ?, ?, ?, ?)
            `)
            .run(
              username,
              email,
              googleId,
              email,
              avatar
            );

          const newUser = db
            .prepare(
              "SELECT * FROM users WHERE id = ?"
            )
            .get(result.lastInsertRowid);

          return done(null, newUser);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
}

/*
|--------------------------------------------------------------------------
| PUBLIC USER DATA
|--------------------------------------------------------------------------
*/

function publicUser(user) {
  return {
    id: user.id,

    username: user.username,

    email:
      user.email ||
      user.google_email ||
      "",

    location: "",

    status: "",

    birthday: "",

    llm: "GPT-5.6 Luna",

    avatar_url:
      user.avatar_url ||
      null,

    googleLinked:
      Boolean(user.google_id)
  };
}

/*
|--------------------------------------------------------------------------
| AUTH MIDDLEWARE
|--------------------------------------------------------------------------
*/

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: "You must be logged in."
    });
  }

  next();
}

/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/

app.get("/api/me", (req, res) => {
  res.json({
    user: req.user
      ? publicUser(req.user)
      : null
  });
});

/*
|--------------------------------------------------------------------------
| REGISTER
|--------------------------------------------------------------------------
*/

app.post("/api/auth/register", async (req, res) => {
  try {
    const username =
      String(req.body.username || "").trim();

    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    /*
     * Validate username.
     */

    if (
      !/^[A-Za-z0-9_]{3,32}$/.test(username)
    ) {
      return res.status(400).json({
        error:
          "Username must be 3-32 characters using letters, numbers, or underscores."
      });
    }

    /*
     * Validate email.
     */

    if (
      !/^\S+@\S+\.\S+$/.test(email)
    ) {
      return res.status(400).json({
        error:
          "Please enter a valid email."
      });
    }

    /*
     * Validate password.
     */

    if (password.length < 8) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters."
      });
    }

    /*
     * Check username.
     */

    const existingUsername = db
      .prepare(
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE"
      )
      .get(username);

    if (existingUsername) {
      return res.status(409).json({
        error:
          "That username is already taken."
      });
    }

    /*
     * Check email.
     */

    const existingEmail = db
      .prepare(
        "SELECT id FROM users WHERE email = ? COLLATE NOCASE"
      )
      .get(email);

    if (existingEmail) {
      return res.status(409).json({
        error:
          "That email is already registered."
      });
    }

    /*
     * Hash password.
     */

    const passwordHash =
      await bcrypt.hash(password, 12);

    /*
     * Create user.
     */

    const result = db
      .prepare(`
        INSERT INTO users (
          username,
          email,
          password_hash
        )

        VALUES (?, ?, ?)
      `)
      .run(
        username,
        email,
        passwordHash
      );

    const user = db
      .prepare(
        "SELECT * FROM users WHERE id = ?"
      )
      .get(result.lastInsertRowid);

    /*
     * Automatically log them in.
     */

    req.login(user, error => {
      if (error) {
        return res.status(500).json({
          error:
            "Account created, but the session could not be started."
        });
      }

      res.json({
        user: publicUser(user)
      });
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Could not create account."
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

app.post("/api/auth/login", async (req, res) => {
  try {
    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    const user = db
      .prepare(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE"
      )
      .get(username);

    /*
     * Do not reveal whether the username exists.
     */

    if (
      !user ||
      !user.password_hash ||
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        error:
          "Incorrect username or password."
      });
    }

    req.login(user, error => {
      if (error) {
        return res.status(500).json({
          error:
            "Could not start your session."
        });
      }

      res.json({
        user: publicUser(user)
      });
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Could not log in."
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/logout",
  (req, res) => {
    req.logout(error => {
      if (error) {
        return res.status(500).json({
          error:
            "Could not log out."
        });
      }

      req.session.destroy(() => {
        res.json({
          ok: true
        });
      });
    });
  }
);

/*
|--------------------------------------------------------------------------
| GOOGLE ROUTES
|--------------------------------------------------------------------------
*/

if (googleConfigured) {
  /*
   * Normal Google login.
   */

  app.get(
    "/auth/google",
    passport.authenticate(
      "google",
      {
        scope: [
          "profile",
          "email"
        ],

        prompt:
          "select_account"
      }
    )
  );

  /*
   * Link Google to an existing account.
   */

  app.get(
    "/auth/google/link",
    requireAuth,
    (req, res, next) => {
      req.session.googleLinkUserId =
        req.user.id;

      passport.authenticate(
        "google",
        {
          scope: [
            "profile",
            "email"
          ],

          prompt:
            "select_account"
        }
      )(req, res, next);
    }
  );

  /*
   * Google callback.
   */

  app.get(
    "/auth/google/callback",

    passport.authenticate(
      "google",
      {
        failureRedirect:
          "/?google=failed"
      }
    ),

    (req, res) => {
      const linkedUserId =
        req.session.googleLinkUserId;

      delete req.session.googleLinkUserId;

      /*
       * If the user was explicitly linking
       * Google, attach the Google information
       * to their existing account.
       */

      if (
        linkedUserId &&
        linkedUserId !== req.user.id
      ) {
        const googleId =
          req.user.google_id;

        const googleEmail =
          req.user.google_email;

        const avatar =
          req.user.avatar_url;

        db.prepare(`
          UPDATE users

          SET google_id = ?,
              google_email = ?,
              avatar_url = ?

          WHERE id = ?
        `).run(
          googleId,
          googleEmail,
          avatar,
          linkedUserId
        );

        const linkedUser =
          db
            .prepare(
              "SELECT * FROM users WHERE id = ?"
            )
            .get(linkedUserId);

        req.login(
          linkedUser,
          () => {
            res.redirect("/");
          }
        );

        return;
      }

      res.redirect("/");
    }
  );
} else {
  /*
   * Friendly error when Google credentials
   * have not been configured yet.
   */

  app.get(
    "/auth/google",
    (_, res) => {
      res
        .status(503)
        .send(
          "Google OAuth is not configured on this server yet."
        );
    }
  );

  app.get(
    "/auth/google/link",
    (_, res) => {
      res
        .status(503)
        .send(
          "Google OAuth is not configured on this server yet."
        );
    }
  );
}

/*
|--------------------------------------------------------------------------
| USER DATA
|--------------------------------------------------------------------------
*/

app.get(
  "/api/data",
  requireAuth,
  (req, res) => {
    /*
     * Contest logs belonging to THIS user.
     */

    const contestLogs =
      db
        .prepare(`
          SELECT
            id,
            title,
            date

          FROM contest_logs

          WHERE user_id = ?

          ORDER BY created_at DESC
        `)
        .all(req.user.id);

    /*
     * Community posts.
     */

    const communityResponses =
      db
        .prepare(`
          SELECT
            p.id,
            u.username AS author,
            p.text,
            p.date,
            p.likes

          FROM community_posts p

          JOIN users u
            ON u.id = p.user_id

          ORDER BY p.created_at DESC
        `)
        .all();

    res.json({
      contestLogs,
      communityResponses
    });
  }
);

/*
|--------------------------------------------------------------------------
| SAVE CONTEST LOG
|--------------------------------------------------------------------------
*/

app.post(
  "/api/contest-logs",
  requireAuth,
  (req, res) => {
    const id =
      Number(req.body.id);

    const title =
      String(
        req.body.title || ""
      ).trim();

    const date =
      String(
        req.body.date || ""
      ).trim();

    if (
      !Number.isSafeInteger(id) ||
      !title ||
      !date
    ) {
      return res.status(400).json({
        error:
          "Invalid contest log."
      });
    }

    /*
     * Notice that user_id comes from
     * the logged-in session, NOT the browser.
     */

    db.prepare(`
      INSERT OR REPLACE INTO contest_logs (
        id,
        user_id,
        title,
        date
      )

      VALUES (?, ?, ?, ?)
    `).run(
      id,
      req.user.id,
      title,
      date
    );

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| COMMUNITY POSTS
|--------------------------------------------------------------------------
*/

app.post(
  "/api/community/posts",
  requireAuth,
  (req, res) => {
    const id =
      Number(req.body.id);

    const text =
      String(
        req.body.text || ""
      ).trim();

    const date =
      String(
        req.body.date || ""
      ).trim();

    if (
      !Number.isSafeInteger(id) ||
      !text ||
      !date
    ) {
      return res.status(400).json({
        error:
          "Invalid post."
      });
    }

    db.prepare(`
      INSERT OR REPLACE INTO community_posts (
        id,
        user_id,
        text,
        date,
        likes
      )

      VALUES (?, ?, ?, ?, 0)
    `).run(
      id,
      req.user.id,
      text,
      date
    );

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| AI
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| The API key stays on the SERVER.
|
| The browser calls:
|
|     /api/ai/chat
|
| and the server calls OpenAI.
|
|--------------------------------------------------------------------------
*/

app.post(
  "/api/ai/chat",
  requireAuth,
  async (req, res) => {
    /*
     * Make sure the server has an API key.
     */

    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({
        error:
          "AI service is not configured. Add OPENAI_API_KEY to the server environment."
      });
    }

    const message =
      String(
        req.body.message || ""
      ).trim();

    if (
      !message ||
      message.length > 4000
    ) {
      return res.status(400).json({
        error:
          "Message must be between 1 and 4000 characters."
      });
    }

    try {
      const client =
        new OpenAI({
          apiKey:
            process.env.OPENAI_API_KEY
        });

      /*
       * Keep only the recent conversation.
       */

      const history =
        Array.isArray(
          req.body.history
        )
          ? req.body.history.slice(-10)
          : [];

      /*
       * Build the conversation.
       */

      const input = [
        {
          role: "developer",

          content:
            "You are the math competition assistant for this website. Help students learn competition mathematics. Prefer explanations and hints over simply giving an answer. Be encouraging, concise, and age-appropriate."
        },

        ...history.map(item => ({
          role:
            item.sender ===
            "GPT-5.6 Luna"
              ? "assistant"
              : "user",

          content:
            String(
              item.text || ""
            ).slice(0, 4000)
        })),

        {
          role: "user",

          content:
            message
        }
      ];

      /*
       * Call GPT-5.6 Luna.
       */

      const response =
        await client.responses.create({
          model:
            "gpt-5.6-luna",

          input
        });

      /*
       * Send the answer back to the browser.
       */

      res.json({
        reply:
          response.output_text ||
          "I wasn't able to generate a response."
      });
    } catch (error) {
      console.error(
        "AI ERROR:",
        error
      );

      res.status(502).json({
        error:
          "The AI service returned an error."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| FRONTEND
|--------------------------------------------------------------------------
*/

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/*
 * If someone visits another URL,
 * send them the main application.
 */

app.get(
  "*",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

app.listen(
  PORT,
  () => {
    console.log(
      `Math Competition Hub running at http://localhost:${PORT}`
    );

    if (!googleConfigured) {
      console.log(
        "Google OAuth is not configured yet."
      );
    }

    if (
      !process.env.OPENAI_API_KEY
    ) {
      console.log(
        "OpenAI API is not configured yet."
      );
    }
  }
);
