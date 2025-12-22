export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    // CORS
    if (req.method === "OPTIONS") return cors(new Response("", { status: 204 }));

    try {
      if (path === "/api/health") return cors(json({ ok: true }));

      if (path === "/api/register" && req.method === "POST") {
        const body = await req.json();
        return cors(await register(env, body));
      }
      if (path === "/api/login" && req.method === "POST") {
        const body = await req.json();
        return cors(await login(env, body));
      }
      if (path === "/api/me" && req.method === "GET") {
        const user = await requireUser(env, req);
        return cors(json({ ok: true, user }));
      }
      if (path === "/api/me" && req.method === "PATCH") {
        const user = await requireUser(env, req);
        const body = await req.json();
        return cors(await updateMe(env, user, body));
      }

      if (path === "/api/claim-ad" && req.method === "POST") {
        const user = await requireUser(env, req);
        return cors(await claimAd(env, user));
      }

      if (path === "/api/predictions" && req.method === "GET") {
        return cors(await listPredictions(env, url));
      }
      if (path === "/api/predictions" && req.method === "POST") {
        const user = await requireUser(env, req);
        const body = await req.json();
        return cors(await createPrediction(env, user, body));
      }

      // /api/predictions/:id
      const predDetail = path.match(/^\/api\/predictions\/([^\/]+)$/);
      if (predDetail && req.method === "GET") {
        return cors(await getPrediction(env, predDetail[1], req));
      }

      // Vote
      const voteMatch = path.match(/^\/api\/predictions\/([^\/]+)\/vote$/);
      if (voteMatch && req.method === "POST") {
        const user = await requireUser(env, req);
        const body = await req.json();
        return cors(await vote(env, user, voteMatch[1], body));
      }

      // Like prediction
      const likePred = path.match(/^\/api\/predictions\/([^\/]+)\/like$/);
      if (likePred && req.method === "POST") {
        const user = await requireUser(env, req);
        return cors(await likePrediction(env, user, likePred[1]));
      }

      // Comments
      const postComment = path.match(/^\/api\/predictions\/([^\/]+)\/comments$/);
      if (postComment && req.method === "POST") {
        const user = await requireUser(env, req);
        const body = await req.json();
        return cors(await addComment(env, user, postComment[1], body));
      }

      // Like comment
      const likeComment = path.match(/^\/api\/comments\/([^\/]+)\/like$/);
      if (likeComment && req.method === "POST") {
        const user = await requireUser(env, req);
        return cors(await likeCommentFn(env, user, likeComment[1]));
      }

      return cors(json({ ok: false, error: "Not found" }, 404));
    } catch (e) {
      return cors(json({ ok: false, error: e?.message || "Server error" }, 500));
    }
  },
};

function cors(res) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return new Response(res.body, { status: res.status, headers: h });
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
function nowMs() { return Date.now(); }
function uuid() {
  // ok for demo; for prod you can use crypto.randomUUID() (available in Workers)
  return crypto.randomUUID();
}

async function sha256Hex(s) {
  const data = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// Very simple password hashing for demo: sha256(salt + password)
// For production, use a stronger KDF (PBKDF2/Argon2) and per-user salt stored in DB.
async function hashPass(email, pass) {
  const salt = await sha256Hex("predictx_salt::" + email);
  return sha256Hex(salt + "::" + pass);
}

async function register(env, body) {
  const email = String(body?.email || "").trim().toLowerCase();
  const pass = String(body?.password || "");
  if (!email || !email.includes("@")) return json({ ok: false, error: "Invalid email" }, 400);
  if (pass.length < 6) return json({ ok: false, error: "Password too short (>=6)" }, 400);

  const db = env.DB;
  const exists = await db.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
  if (exists) return json({ ok: false, error: "Email already registered" }, 409);

  const passHash = await hashPass(email, pass);
  const ts = nowMs();

  await db.prepare(`
    INSERT INTO users(email, pass_hash, nick, bio, tier, level, win_rate, gc, created_at, updated_at)
    VALUES(?, ?, 'Guest', '', 4, 1, 50, 2500, ?, ?)
  `).bind(email, passHash, ts, ts).run();

  return json({ ok: true });
}

async function login(env, body) {
  const email = String(body?.email || "").trim().toLowerCase();
  const pass = String(body?.password || "");
  const db = env.DB;

  const row = await db.prepare("SELECT id, pass_hash FROM users WHERE email=?").bind(email).first();
  if (!row) return json({ ok: false, error: "Invalid credentials" }, 401);

  const passHash = await hashPass(email, pass);
  if (passHash !== row.pass_hash) return json({ ok: false, error: "Invalid credentials" }, 401);

  const token = await sha256Hex(uuid() + "::" + email + "::" + nowMs());
  const expires = nowMs() + 7 * 24 * 60 * 60 * 1000; // 7 days

  await db.prepare("INSERT INTO sessions(token, user_id, expires_at) VALUES(?, ?, ?)").bind(token, row.id, expires).run();
  return json({ ok: true, token });
}

async function requireUser(env, req) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) throw new Error("Unauthorized");

  const db = env.DB;
  const sess = await db.prepare("SELECT user_id, expires_at FROM sessions WHERE token=?").bind(token).first();
  if (!sess) throw new Error("Unauthorized");
  if (Number(sess.expires_at) < nowMs()) throw new Error("Session expired");

  const user = await db.prepare(`
    SELECT id, email, nick, bio, tier, level, win_rate as winRate, gc
    FROM users WHERE id=?
  `).bind(sess.user_id).first();

  if (!user) throw new Error("Unauthorized");
  return { ...user, token };
}

async function updateMe(env, user, body) {
  const nick = String(body?.nick ?? user.nick).trim().slice(0, 20);
  const bio = String(body?.bio ?? user.bio).trim().slice(0, 140);
  const tier = clampInt(body?.tier ?? user.tier, 1, 10);
  const level = clampInt(body?.level ?? user.level, 1, 999);
  const winRate = clampInt(body?.winRate ?? user.winRate, 0, 100);

  const ts = nowMs();
  await env.DB.prepare(`
    UPDATE users SET nick=?, bio=?, tier=?, level=?, win_rate=?, updated_at=? WHERE id=?
  `).bind(nick, bio, tier, level, winRate, ts, user.id).run();

  const me = await env.DB.prepare(`
    SELECT id, email, nick, bio, tier, level, win_rate as winRate, gc
    FROM users WHERE id=?
  `).bind(user.id).first();

  return json({ ok: true, user: me });
}

async function claimAd(env, user) {
  const COOLDOWN = 12 * 60 * 60 * 1000;
  const REWARD = 100;

  const db = env.DB;
  const row = await db.prepare("SELECT last_claim_at FROM ad_claims WHERE user_id=?").bind(user.id).first();
  const last = row ? Number(row.last_claim_at) : 0;
  const now = nowMs();

  if (last + COOLDOWN > now) {
    const remaining = last + COOLDOWN - now;
    return json({ ok: false, error: "Cooldown", remainingMs: remaining }, 409);
  }

  // upsert claim + add gc
  await db.prepare("INSERT INTO ad_claims(user_id, last_claim_at) VALUES(?, ?) ON CONFLICT(user_id) DO UPDATE SET last_claim_at=excluded.last_claim_at")
    .bind(user.id, now).run();

  await db.prepare("UPDATE users SET gc = gc + ? , updated_at=? WHERE id=?").bind(REWARD, now, user.id).run();

  const me = await db.prepare("SELECT gc FROM users WHERE id=?").bind(user.id).first();
  return json({ ok: true, reward: REWARD, newBalance: me.gc });
}

async function listPredictions(env, url) {
  const tag = (url.searchParams.get("tag") || "all").trim();
  const hot = (url.searchParams.get("hot") || "day").trim(); // day/week/month/all
  const q = (url.searchParams.get("q") || "").trim().toLowerCase();

  // Hot score = votes within period + 0.12*totalVotes (simple)
  const periodMs = hot === "day" ? 1 : hot === "week" ? 7 : hot === "month" ? 30 : 36500;
  const since = nowMs() - periodMs * 24 * 60 * 60 * 1000;

  // We'll compute "recentVotes" by votes table created_at >= since
  // If hot=all, recentVotes = totalVotes.
  const where = [];
  const bind = [];

  if (tag !== "all") { where.push("p.tag=?"); bind.push(tag); }
  // q filter (title contains)
  if (q) { where.push("LOWER(p.title) LIKE ?"); bind.push(`%${q}%`); }

  const whereSql = where.length ? ("WHERE " + where.join(" AND ")) : "";

  const sql = `
    SELECT
      p.id, p.title, p.tag, p.settle_date as settleDate, p.cover_url as coverUrl, p.created_at as createdAt,
      (SELECT COUNT(*) FROM prediction_likes pl WHERE pl.pred_id=p.id) as likes,
      (SELECT COUNT(*) FROM comments c WHERE c.pred_id=p.id) as commentsCount,
      (SELECT SUM(o.votes) FROM prediction_options o WHERE o.pred_id=p.id) as totalVotes,
      ${
        hot === "all"
          ? `(SELECT SUM(o.votes) FROM prediction_options o WHERE o.pred_id=p.id)`
          : `(SELECT COUNT(*) FROM prediction_votes v WHERE v.pred_id=p.id AND v.created_at >= ${since})`
      } as recentVotes
    FROM predictions p
    ${whereSql}
    ORDER BY (recentVotes + CAST(0.12 * COALESCE(totalVotes,0) AS INT)) DESC, p.created_at DESC
    LIMIT 50
  `;

  const rows = await env.DB.prepare(sql).bind(...bind).all();

  // attach top2 heart comments
  const list = [];
  for (const r of rows.results) {
    const top2 = await env.DB.prepare(`
      SELECT c.id, c.author_nick as authorNick, c.text, c.created_at as createdAt,
        (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id=c.id) as likes
      FROM comments c
      WHERE c.pred_id=?
      ORDER BY likes DESC, c.created_at DESC
      LIMIT 2
    `).bind(r.id).all();

    list.push({
      ...r,
      totalVotes: Number(r.totalVotes || 0),
      likes: Number(r.likes || 0),
      commentsCount: Number(r.commentsCount || 0),
      topComments: top2.results.map(x => ({
        id: x.id, author: x.authorNick, text: x.text, createdAt: x.createdAt, likes: Number(x.likes || 0)
      }))
    });
  }

  return json({ ok: true, predictions: list });
}

async function createPrediction(env, user, body) {
  const fee = 1000;
  if (user.tier < 4) return json({ ok: false, error: "Tier too low (need >=4)" }, 403);

  const title = String(body?.title || "").trim();
  const tag = String(body?.tag || "").trim();
  const settleDate = String(body?.settleDate || "").trim();
  const coverUrl = String(body?.coverUrl || "").trim().slice(0, 400);
  const options = Array.isArray(body?.options) ? body.options.map(s => String(s).trim()).filter(Boolean) : [];

  if (title.length < 5 || title.length > 120) return json({ ok: false, error: "Invalid title" }, 400);
  if (!tag) return json({ ok: false, error: "Invalid tag" }, 400);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(settleDate)) return json({ ok: false, error: "Invalid settleDate" }, 400);
  if (options.length < 2 || options.length > 12) return json({ ok: false, error: "Options must be 2-12" }, 400);

  const db = env.DB;

  // ensure enough gc
  const me = await db.prepare("SELECT gc FROM users WHERE id=?").bind(user.id).first();
  if (!me || Number(me.gc) < fee) return json({ ok: false, error: "Not enough GC" }, 409);

  const predId = uuid();
  const ts = nowMs();

  // transaction-like sequence (D1 doesn't support multi-stmt txn via API easily; but for demo ok)
  await db.prepare("UPDATE users SET gc = gc - ?, updated_at=? WHERE id=?").bind(fee, ts, user.id).run();

  await db.prepare(`
    INSERT INTO predictions(id, owner_user_id, title, tag, settle_date, cover_url, status, created_at)
    VALUES(?, ?, ?, ?, ?, ?, 'open', ?)
  `).bind(predId, user.id, title, tag, settleDate, coverUrl, ts).run();

  for (const opt of options) {
    const optId = uuid();
    await db.prepare(`
      INSERT INTO prediction_options(id, pred_id, text, votes) VALUES(?, ?, ?, 0)
    `).bind(optId, predId, opt.slice(0, 60)).run();
  }

  return json({ ok: true, predId });
}

async function getPrediction(env, predId, req) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  let viewer = null;
  if (token) {
    try { viewer = await requireUser(env, req); } catch {}
  }

  const db = env.DB;
  const p = await db.prepare(`
    SELECT p.id, p.title, p.tag, p.settle_date as settleDate, p.cover_url as coverUrl, p.created_at as createdAt,
      (SELECT COUNT(*) FROM prediction_likes pl WHERE pl.pred_id=p.id) as likes,
      (SELECT COUNT(*) FROM comments c WHERE c.pred_id=p.id) as commentsCount
    FROM predictions p WHERE p.id=?
  `).bind(predId).first();

  if (!p) return json({ ok: false, error: "Not found" }, 404);

  const opts = await db.prepare(`
    SELECT id, text, votes FROM prediction_options WHERE pred_id=? ORDER BY rowid ASC
  `).bind(predId).all();

  const comments = await db.prepare(`
    SELECT c.id, c.author_nick as author, c.text, c.created_at as createdAt,
      (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id=c.id) as likes
    FROM comments c
    WHERE c.pred_id=?
    ORDER BY c.created_at DESC
    LIMIT 200
  `).bind(predId).all();

  const totalVotes = opts.results.reduce((a, o) => a + Number(o.votes || 0), 0);

  let myVote = null;
  let likedByMe = false;
  if (viewer) {
    const mv = await db.prepare("SELECT option_id FROM prediction_votes WHERE pred_id=? AND user_id=?")
      .bind(predId, viewer.id).first();
    myVote = mv?.option_id || null;

    const pl = await db.prepare("SELECT 1 FROM prediction_likes WHERE pred_id=? AND user_id=?")
      .bind(predId, viewer.id).first();
    likedByMe = !!pl;
  }

  return json({
    ok: true,
    prediction: {
      ...p,
      likes: Number(p.likes || 0),
      commentsCount: Number(p.commentsCount || 0),
      totalVotes,
      likedByMe,
      myVote,
      options: opts.results.map(o => ({ id: o.id, text: o.text, votes: Number(o.votes || 0) })),
      comments: comments.results.map(c => ({
        id: c.id, author: c.author, text: c.text, createdAt: c.createdAt, likes: Number(c.likes || 0)
      })),
    }
  });
}

async function vote(env, user, predId, body) {
  const optionId = String(body?.optionId || "").trim();
  if (!optionId) return json({ ok: false, error: "Missing optionId" }, 400);

  const db = env.DB;

  // Ensure prediction + option exist
  const okPred = await db.prepare("SELECT id FROM predictions WHERE id=?").bind(predId).first();
  if (!okPred) return json({ ok: false, error: "Not found" }, 404);

  const opt = await db.prepare("SELECT id FROM prediction_options WHERE id=? AND pred_id=?")
    .bind(optionId, predId).first();
  if (!opt) return json({ ok: false, error: "Invalid option" }, 400);

  const exists = await db.prepare("SELECT option_id FROM prediction_votes WHERE pred_id=? AND user_id=?")
    .bind(predId, user.id).first();

  if (exists) return json({ ok: false, error: "Already voted" }, 409);

  const ts = nowMs();
  await db.prepare("INSERT INTO prediction_votes(pred_id, user_id, option_id, created_at) VALUES(?,?,?,?)")
    .bind(predId, user.id, optionId, ts).run();
  await db.prepare("UPDATE prediction_options SET votes=votes+1 WHERE id=?").bind(optionId).run();

  return json({ ok: true });
}

async function likePrediction(env, user, predId) {
  const db = env.DB;
  const exists = await db.prepare("SELECT 1 FROM prediction_likes WHERE pred_id=? AND user_id=?")
    .bind(predId, user.id).first();

  if (exists) {
    await db.prepare("DELETE FROM prediction_likes WHERE pred_id=? AND user_id=?").bind(predId, user.id).run();
    return json({ ok: true, liked: false });
  } else {
    await db.prepare("INSERT INTO prediction_likes(pred_id, user_id, created_at) VALUES(?,?,?)")
      .bind(predId, user.id, nowMs()).run();
    return json({ ok: true, liked: true });
  }
}

async function addComment(env, user, predId, body) {
  const text = String(body?.text || "").trim();
  if (!text || text.length > 300) return json({ ok: false, error: "Invalid text" }, 400);

  const db = env.DB;
  const okPred = await db.prepare("SELECT id FROM predictions WHERE id=?").bind(predId).first();
  if (!okPred) return json({ ok: false, error: "Not found" }, 404);

  const me = await db.prepare("SELECT nick FROM users WHERE id=?").bind(user.id).first();

  const id = uuid();
  const ts = nowMs();
  await db.prepare("INSERT INTO comments(id, pred_id, user_id, author_nick, text, created_at) VALUES(?,?,?,?,?,?)")
    .bind(id, predId, user.id, me?.nick || "User", text, ts).run();

  return json({ ok: true, commentId: id });
}

async function likeCommentFn(env, user, commentId) {
  const db = env.DB;
  const exists = await db.prepare("SELECT 1 FROM comment_likes WHERE comment_id=? AND user_id=?")
    .bind(commentId, user.id).first();

  if (exists) {
    await db.prepare("DELETE FROM comment_likes WHERE comment_id=? AND user_id=?")
      .bind(commentId, user.id).run();
    return json({ ok: true, liked: false });
  } else {
    await db.prepare("INSERT INTO comment_likes(comment_id, user_id, created_at) VALUES(?,?,?)")
      .bind(commentId, user.id, nowMs()).run();
    return json({ ok: true, liked: true });
  }
}

function clampInt(v, min, max) {
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) return min;
  return Math.max(min, Math.min(max, n));
}
