-- USERS
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  nick TEXT NOT NULL DEFAULT 'Guest',
  bio TEXT NOT NULL DEFAULT '',
  tier INTEGER NOT NULL DEFAULT 1,
  level INTEGER NOT NULL DEFAULT 1,
  win_rate INTEGER NOT NULL DEFAULT 50,
  gc INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- SESSIONS (token -> user)
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- PREDICTIONS
CREATE TABLE IF NOT EXISTS predictions (
  id TEXT PRIMARY KEY,
  owner_user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  tag TEXT NOT NULL,
  settle_date TEXT NOT NULL,
  cover_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL
);

-- OPTIONS
CREATE TABLE IF NOT EXISTS prediction_options (
  id TEXT PRIMARY KEY,
  pred_id TEXT NOT NULL,
  text TEXT NOT NULL,
  votes INTEGER NOT NULL DEFAULT 0
);

-- USER VOTE (one user one option per prediction)
CREATE TABLE IF NOT EXISTS prediction_votes (
  pred_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  option_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (pred_id, user_id)
);

-- COMMENTS
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  pred_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  author_nick TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- LIKES: prediction
CREATE TABLE IF NOT EXISTS prediction_likes (
  pred_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (pred_id, user_id)
);

-- LIKES: comment
CREATE TABLE IF NOT EXISTS comment_likes (
  comment_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (comment_id, user_id)
);

-- AD CLAIM COOLDOWN
CREATE TABLE IF NOT EXISTS ad_claims (
  user_id INTEGER PRIMARY KEY,
  last_claim_at INTEGER NOT NULL
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_predictions_tag_created ON predictions(tag, created_at);
CREATE INDEX IF NOT EXISTS idx_comments_pred_created ON comments(pred_id, created_at);
