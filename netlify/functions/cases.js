// netlify/functions/cases.js — with Auth, Roles, Sessions, Action Logs
const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");
 
function getDb() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set");
  return neon(process.env.DATABASE_URL);
}
 
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, X-Session-Token",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Content-Type": "application/json",
};
 
function resp(s, b) { return { statusCode: s, headers: CORS, body: JSON.stringify(b) }; }
 
// ── CRYPTO HELPERS ──────────────────────────────────────────────────────────
function hashPassword(password, salt) {
  return crypto.createHmac("sha256", salt).update(password).digest("hex");
}
function genSalt() { return crypto.randomBytes(16).toString("hex"); }
function genToken() { return crypto.randomBytes(32).toString("hex"); }
 
// ── AUTH HELPERS ────────────────────────────────────────────────────────────
async function getSession(sql, token) {
  if (!token) return null;
  const [s] = await sql`
    SELECT s.*, u.username, u.display_name, u.role
    FROM user_sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ${token}
      AND s.expires_at > NOW()
      AND u.is_active = true
  `;
  return s || null;
}
 
async function requireAuth(sql, token, requireAdmin = false) {
  const session = await getSession(sql, token);
  if (!session) return { error: "Unauthorized", status: 401 };
  if (requireAdmin && session.role !== "admin") return { error: "Forbidden", status: 403 };
  return { session };
}
 
// ── INIT DB ─────────────────────────────────────────────────────────────────
async function initDb(sql) {
  // Users table
  await sql`CREATE TABLE IF NOT EXISTS users (
    id           SERIAL PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt         TEXT NOT NULL,
    role         TEXT DEFAULT 'user',
    is_active    BOOLEAN DEFAULT true,
    must_change_password BOOLEAN DEFAULT true,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
  )`;
 
  // Sessions table
  await sql`CREATE TABLE IF NOT EXISTS user_sessions (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '8 hours',
    last_seen  TIMESTAMPTZ DEFAULT NOW()
  )`;
 
  // Cases table
  await sql`CREATE TABLE IF NOT EXISTS enforcement_cases (
    id TEXT PRIMARY KEY, sanuan TEXT, owner TEXT, hmvad TEXT, action TEXT, next_step TEXT,
    amount NUMERIC(12,2) DEFAULT 0, loan_type TEXT, work_of TEXT, asset TEXT, result TEXT,
    money_recv NUMERIC(12,2) DEFAULT 0, priority INTEGER DEFAULT 0, priority_tag TEXT,
    salary_result TEXT, bank_result TEXT, land_result TEXT, send_oa TEXT,
    attach_type TEXT, attach_detail TEXT, charge TEXT, action_status TEXT DEFAULT '',
    due_date DATE, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
  )`;
 
  // Notes table
  await sql`CREATE TABLE IF NOT EXISTS case_notes (
    id SERIAL PRIMARY KEY,
    case_id TEXT REFERENCES enforcement_cases(id) ON DELETE CASCADE,
    note_text TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
 
  // Action logs table
  await sql`CREATE TABLE IF NOT EXISTS action_logs (
    id SERIAL PRIMARY KEY,
    case_id TEXT REFERENCES enforcement_cases(id) ON DELETE CASCADE,
    changed_by TEXT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action_type TEXT,
    field_name TEXT,
    old_value TEXT,
    new_value TEXT,
    note TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
 
  // Indexes for performance
  await sql`CREATE INDEX IF NOT EXISTS idx_ec_owner ON enforcement_cases(owner)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_ec_hmvad ON enforcement_cases(hmvad)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_ec_action_status ON enforcement_cases(action_status)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_ec_due_date ON enforcement_cases(due_date)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_ec_priority ON enforcement_cases(priority DESC)`;

  // Create default admin if not exists
  const [existing] = await sql`SELECT id FROM users WHERE username = 'admin'`;
  if (!existing) {
    const salt = genSalt();
    const hash = hashPassword("Admin@1234", salt);
    await sql`INSERT INTO users (username, display_name, password_hash, salt, role, must_change_password)
      VALUES ('admin', 'Administrator', ${hash}, ${salt}, 'admin', true)`;
  }
 
  return { ok: true, message: "Tables ready. Default admin: admin / Admin@1234 (must change on first login)" };
}
 
// ── AUTH: LOGIN ─────────────────────────────────────────────────────────────
async function login(sql, body, event) {
  const { username, password } = body;
  if (!username || !password) return { ok: false, error: "กรุณากรอก username และ password" };
 
  const [user] = await sql`SELECT * FROM users WHERE username = ${username.trim().toLowerCase()}`;
  if (!user) return { ok: false, error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" };
 
  // Check if account is locked
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    const remaining = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
    return { ok: false, error: `Account ถูกล็อค อีก ${remaining} นาที` };
  }
  if (!user.is_active) return { ok: false, error: "Account ถูกระงับการใช้งาน" };
 
  // Verify password
  const hash = hashPassword(password, user.salt);
  if (hash !== user.password_hash) {
    const attempts = user.failed_attempts + 1;
    if (attempts >= 5) {
      // Lock for 30 minutes
      await sql`UPDATE users SET failed_attempts=${attempts}, locked_until=NOW()+INTERVAL '30 minutes' WHERE id=${user.id}`;
      return { ok: false, error: "Login ผิด 5 ครั้ง Account ถูกล็อค 30 นาที" };
    }
    await sql`UPDATE users SET failed_attempts=${attempts} WHERE id=${user.id}`;
    return { ok: false, error: `รหัสผ่านไม่ถูกต้อง (เหลืออีก ${5 - attempts} ครั้ง)` };
  }
 
  // Success - reset failed attempts
  await sql`UPDATE users SET failed_attempts=0, locked_until=null, updated_at=NOW() WHERE id=${user.id}`;
 
  // Create session (8 hours)
  const token = genToken();
  const ip = event.headers["x-forwarded-for"] || event.headers["client-ip"] || "";
  const ua = event.headers["user-agent"] || "";
  await sql`INSERT INTO user_sessions (user_id, token, ip_address, user_agent)
    VALUES (${user.id}, ${token}, ${ip}, ${ua})`;
 
  return {
    ok: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      role: user.role,
      must_change_password: user.must_change_password,
    }
  };
}
 
// ── AUTH: LOGOUT ────────────────────────────────────────────────────────────
async function logout(sql, token) {
  await sql`DELETE FROM user_sessions WHERE token = ${token}`;
  return { ok: true };
}
 
// ── AUTH: CHANGE PASSWORD ───────────────────────────────────────────────────
async function changePassword(sql, session, body) {
  const { old_password, new_password } = body;
  if (!new_password || new_password.length < 8) return { ok: false, error: "รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร" };
 
  const [user] = await sql`SELECT * FROM users WHERE id = ${session.user_id}`;
  const oldHash = hashPassword(old_password, user.salt);
  if (oldHash !== user.password_hash) return { ok: false, error: "รหัสผ่านเดิมไม่ถูกต้อง" };
 
  const salt = genSalt();
  const hash = hashPassword(new_password, salt);
  await sql`UPDATE users SET password_hash=${hash}, salt=${salt}, must_change_password=false, updated_at=NOW() WHERE id=${user.id}`;
  return { ok: true };
}
 
// ── ADMIN: GET USERS ────────────────────────────────────────────────────────
async function getUsers(sql) {
  return await sql`SELECT id, username, display_name, role, is_active, must_change_password, failed_attempts, locked_until, created_at FROM users ORDER BY id`;
}
 
// ── ADMIN: CREATE USER ──────────────────────────────────────────────────────
async function createUser(sql, body) {
  const { username, display_name, password, role } = body;
  if (!username || !password) return { ok: false, error: "กรุณากรอก username และ password" };
  const salt = genSalt();
  const hash = hashPassword(password, salt);
  const [user] = await sql`
    INSERT INTO users (username, display_name, password_hash, salt, role)
    VALUES (${username.trim().toLowerCase()}, ${display_name||username}, ${hash}, ${salt}, ${role||'user'})
    RETURNING id, username, display_name, role`;
  return { ok: true, user };
}
 
// ── ADMIN: TOGGLE USER ──────────────────────────────────────────────────────
async function toggleUser(sql, userId, action) {
  if (action === 'unlock') {
    await sql`UPDATE users SET failed_attempts=0, locked_until=null WHERE id=${parseInt(userId)}`;
  } else if (action === 'deactivate') {
    await sql`UPDATE users SET is_active=false WHERE id=${parseInt(userId)}`;
  } else if (action === 'activate') {
    await sql`UPDATE users SET is_active=true WHERE id=${parseInt(userId)}`;
  } else if (action === 'reset') {
    const salt = genSalt();
    const hash = hashPassword("Reset@1234", salt);
    await sql`UPDATE users SET password_hash=${hash}, salt=${salt}, must_change_password=true, failed_attempts=0, locked_until=null WHERE id=${parseInt(userId)}`;
  }
  return { ok: true };
}
 
// ── CASES ────────────────────────────────────────────────────────────────────
async function writeLog(sql, caseId, userId, displayName, actionType, changes, note = "") {
  for (const [field, { old: o, new: n }] of Object.entries(changes)) {
    if (String(o ?? '') === String(n ?? '')) continue;
    await sql`INSERT INTO action_logs (case_id, user_id, changed_by, action_type, field_name, old_value, new_value, note)
      VALUES (${caseId}, ${userId||null}, ${displayName||'user'}, ${actionType}, ${field}, ${String(o??'')}, ${String(n??'')}, ${note})`;
  }
}
 
async function getCases(sql, qs) {
  const { stage, result, owner, status, due, q, page, limit: limitParam, all } = qs;
  const fetchAll = all === 'true';
  const pageSize = fetchAll ? null : Math.min(Math.max(parseInt(limitParam)||50, 1), 200);
  const pageNum  = fetchAll ? 1 : Math.max(parseInt(page)||1, 1);
  const offset   = fetchAll ? 0 : (pageNum - 1) * pageSize;
  let cond = [], params = [], idx = 1;
  if (stage)  { cond.push(`hmvad LIKE $${idx}`); params.push(stage+"%"); idx++; }
  if (result) { cond.push(`result = $${idx}`); params.push(result); idx++; }
  if (owner)  { cond.push(`owner = $${idx}`); params.push(owner); idx++; }
  if (status) { cond.push(`action_status = $${idx}`); params.push(status); idx++; }
  if (q) { cond.push(`(id ILIKE $${idx} OR sanuan ILIKE $${idx} OR owner ILIKE $${idx} OR action ILIKE $${idx})`); params.push("%"+q+"%"); idx++; }
  if (due === "overdue") cond.push(`due_date < CURRENT_DATE AND action_status != 'done'`);
  else if (due === "today") cond.push(`due_date = CURRENT_DATE`);
  else if (due === "soon")  cond.push(`due_date >= CURRENT_DATE AND due_date <= CURRENT_DATE + INTERVAL '7 days'`);
  const where = cond.length ? "WHERE "+cond.join(" AND ") : "";
  const orderBy = "ORDER BY priority DESC, amount DESC";
  const limitClause = fetchAll ? "" : `LIMIT ${pageSize} OFFSET ${offset}`;
  const cases = await sql(`SELECT * FROM enforcement_cases ${where} ${orderBy} ${limitClause}`, params);
  const [{ total }] = await sql(`SELECT COUNT(*)::int AS total FROM enforcement_cases ${where}`, params);
  return { cases, total, page: pageNum, pageSize: pageSize || total };
}

async function getCaseNotes(sql, caseId) {
  return await sql`SELECT id, note_text AS text, created_at AS time FROM case_notes WHERE case_id=${caseId} ORDER BY created_at DESC`;
}

async function getOwners(sql) {
  const rows = await sql`SELECT DISTINCT owner FROM enforcement_cases WHERE owner IS NOT NULL AND owner != '' ORDER BY owner`;
  return rows.map(r => r.owner);
}
 
async function upsertCase(sql, c) {
  await sql`INSERT INTO enforcement_cases (id,sanuan,owner,hmvad,action,next_step,amount,loan_type,work_of,asset,result,money_recv,priority,priority_tag,salary_result,bank_result,land_result,send_oa,attach_type,attach_detail,charge,action_status,due_date)
    VALUES (${c.id},${c.sanuan||''},${c.owner||''},${c.hmvad||''},${c.action||''},${c.next_step||''},${c.amount||0},${c.loan_type||''},${c.work_of||''},${c.asset||''},${c.result||''},${c.money_recv||0},${c.priority||0},${c.priority_tag||'low'},${c.salary_result||''},${c.bank_result||''},${c.land_result||''},${c.send_oa||''},${c.attach_type||''},${c.attach_detail||''},${c.charge||''},${c.action_status||''},${c.due_date||null})
    ON CONFLICT (id) DO UPDATE SET sanuan=EXCLUDED.sanuan,owner=EXCLUDED.owner,hmvad=EXCLUDED.hmvad,action=EXCLUDED.action,next_step=EXCLUDED.next_step,amount=EXCLUDED.amount,loan_type=EXCLUDED.loan_type,work_of=EXCLUDED.work_of,asset=EXCLUDED.asset,result=EXCLUDED.result,money_recv=EXCLUDED.money_recv,priority=EXCLUDED.priority,priority_tag=EXCLUDED.priority_tag,salary_result=EXCLUDED.salary_result,bank_result=EXCLUDED.bank_result,land_result=EXCLUDED.land_result,send_oa=EXCLUDED.send_oa,attach_type=EXCLUDED.attach_type,attach_detail=EXCLUDED.attach_detail,charge=EXCLUDED.charge,action_status=EXCLUDED.action_status,due_date=EXCLUDED.due_date,updated_at=NOW()`;
  return { ok: true, id: c.id };
}
 
async function patchCase(sql, id, body, session) {
  const [before] = await sql`SELECT * FROM enforcement_cases WHERE id=${id}`;
  if (!before) return { ok: false, error: "Case not found" };
  const fields=[], vals=[], changes={};
  let i=1;
  const allowed={
    action_status:"action_status", due_date:"due_date", action:"action", hmvad:"hmvad",
    result:"result", money_recv:"money_recv", amount:"amount",
    owner:"owner", loan_type:"loan_type", asset:"asset",
    salary_result:"salary_result", bank_result:"bank_result", land_result:"land_result",
    send_oa:"send_oa", next_step:"next_step", sanuan:"sanuan",
    priority:"priority", priority_tag:"priority_tag"
  };
  for (const [k,col] of Object.entries(allowed)) {
    if (body[k] !== undefined) {
      const nv = body[k]==="" ? null : body[k];
      fields.push(`${col} = $${i}`); vals.push(nv); i++;
      changes[col] = { old: before[col], new: nv };
    }
  }
  if (!fields.length) return { ok: false, error: "No fields" };
  fields.push(`updated_at = NOW()`); vals.push(id);
  await sql(`UPDATE enforcement_cases SET ${fields.join(", ")} WHERE id = $${i}`, vals);
  await writeLog(sql, id, session.user_id, session.display_name, 'EDIT', changes, body.note||'');
  // Update session last_seen
  await sql`UPDATE user_sessions SET last_seen=NOW() WHERE token=${session.token}`;
  return { ok: true };
}
 
async function addNote(sql, caseId, body, session) {
  const [row] = await sql`INSERT INTO case_notes (case_id,note_text) VALUES (${caseId},${body.text}) RETURNING id,note_text,created_at`;
  await writeLog(sql, caseId, session.user_id, session.display_name, 'NOTE', { note_text:{old:'',new:body.text} }, body.text);
  return row;
}
 
async function deleteNote(sql, noteId) {
  await sql`DELETE FROM case_notes WHERE id=${parseInt(noteId)}`;
  return { ok: true };
}
 
async function bulkSeed(sql, body) {
  const { cases } = body;
  if (!Array.isArray(cases)||!cases.length) return { ok:false, error:"No cases" };
  let count=0;
  for (const c of cases) { await upsertCase(sql,c); count++; }
  return { ok:true, inserted:count };
}
 
async function getStatsByOwner(sql) {
  return await sql`
    SELECT owner,
      COUNT(*)::int AS total,
      SUM(amount)::numeric AS total_claimed,
      SUM(money_recv)::numeric AS total_recv,
      COUNT(*) FILTER(WHERE result='ได้เงิน')::int AS got_money,
      COUNT(*) FILTER(WHERE action_status='done')::int AS done_count,
      COUNT(*) FILTER(WHERE due_date < CURRENT_DATE AND action_status != 'done')::int AS overdue
    FROM enforcement_cases
    WHERE owner IS NOT NULL AND owner != ''
    GROUP BY owner ORDER BY total DESC
  `;
}

async function bulkImport(sql, body, session) {
  const { cases } = body;
  if (!Array.isArray(cases) || !cases.length) return { ok: false, error: "ไม่มีข้อมูล" };
  if (cases.length > 500) return { ok: false, error: "นำเข้าได้สูงสุด 500 แถวต่อครั้ง" };
  let count = 0;
  for (const c of cases) {
    if (!c.id) continue;
    await upsertCase(sql, c);
    count++;
  }
  await writeLog(sql, cases[0]?.id || 'bulk', session.user_id, session.display_name, 'IMPORT', { imported: { old: '0', new: String(count) } }, `นำเข้า ${count} เคส`);
  return { ok: true, imported: count };
}

async function getStats(sql) {
  const [row] = await sql`SELECT COUNT(*)::int AS total,SUM(amount)::numeric AS total_claimed,SUM(money_recv)::numeric AS total_recv,COUNT(*) FILTER(WHERE asset='มีทรัพย์สิน')::int AS has_asset,COUNT(*) FILTER(WHERE result='ได้เงิน')::int AS got_money,COUNT(*) FILTER(WHERE result LIKE '%ไม่ได้เงิน%')::int AS no_money,COUNT(*) FILTER(WHERE result='รอผล')::int AS pending,COUNT(*) FILTER(WHERE due_date<CURRENT_DATE AND action_status!='done')::int AS overdue,COUNT(*) FILTER(WHERE action_status='done')::int AS done_count FROM enforcement_cases`;
  const r=parseFloat(row.total_recv)||0,c=parseFloat(row.total_claimed)||1;
  return { ...row, recovery_rate:Math.round(r/c*1000)/10 };
}
 
async function getLogs(sql, caseId, limit=50) {
  const cap = Math.min(Math.max(parseInt(limit)||50, 1), 500);
  return await sql`SELECT * FROM action_logs WHERE case_id=${caseId} ORDER BY created_at DESC LIMIT ${cap}`;
}

async function getAllLogs(sql, limit=100) {
  const cap = Math.min(Math.max(parseInt(limit)||100, 1), 1000);
  return await sql`SELECT l.*,c.sanuan FROM action_logs l LEFT JOIN enforcement_cases c ON c.id=l.case_id ORDER BY l.created_at DESC LIMIT ${cap}`;
}
 
// ── MAIN HANDLER ────────────────────────────────────────────────────────────
// ── GET /online ─────────────────────────────────────────────────────────────
async function getOnlineUsers(sql) {
  const rows = await sql`
    SELECT DISTINCT ON (s.user_id)
      u.display_name, u.role,
      s.last_seen, s.ip_address,
      s.created_at AS session_start
    FROM user_sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.last_seen > NOW() - INTERVAL '15 minutes'
      AND s.expires_at > NOW()
    ORDER BY s.user_id, s.last_seen DESC
  `;
  return rows;
}
 
exports.handler = async (event) => {
  if (event.httpMethod==="OPTIONS") return {statusCode:200,headers:CORS,body:""};
  let sql;
  try { sql=getDb(); } catch(e) { return resp(500,{error:e.message}); }
 
  const method  = event.httpMethod;
  const path    = (event.path||"").replace(/^\/\.netlify\/functions\/cases/,"");
  const qs      = event.queryStringParameters||{};
  const token   = event.headers["x-session-token"]||"";
  let body={};
  try { if(event.body) body=JSON.parse(event.body); } catch(_){}
 
  try {
    // ── Public routes (no auth needed) ──
    if(method==="POST" && path==="/init")   return resp(200, await initDb(sql));
    if(method==="POST" && path==="/login")  return resp(200, await login(sql, body, event));
    if(method==="POST" && path==="/seed") {
      // Allow seed only if cases table is empty
      const [cnt] = await sql`SELECT COUNT(*)::int as c FROM enforcement_cases`;
      if (cnt.c > 0) return resp(400, {error:`ข้อมูลมีอยู่แล้ว ${cnt.c} เคส ไม่สามารถ seed ซ้ำได้`});
      return resp(200, await bulkSeed(sql, body));
    }
 
    // ── Auth check for all other routes ──
    const session = await getSession(sql, token);
    if (!session) return resp(401, {error:"กรุณา Login ก่อนใช้งาน"});
 
    // Attach token to session object for later use
    session.token = token;
 
    if(method==="POST" && path==="/logout")          return resp(200, await logout(sql,token));
    if(method==="POST" && path==="/change-password") return resp(200, await changePassword(sql,session,body));
    if(method==="GET"  && path==="/me")              return resp(200, {user:{id:session.user_id,username:session.username,display_name:session.display_name,role:session.role,must_change_password:session.must_change_password}});
 
    // Admin-only routes
    if(method==="GET"  && path==="/users") {
      if(session.role!=='admin') return resp(403,{error:"เฉพาะ Admin เท่านั้น"});
      return resp(200, {users: await getUsers(sql)});
    }
    if(method==="POST" && path==="/users") {
      if(session.role!=='admin') return resp(403,{error:"เฉพาะ Admin เท่านั้น"});
      return resp(200, await createUser(sql,body));
    }
    const tuMatch = path.match(/^\/users\/(\d+)\/(\w+)$/);
    if(method==="POST" && tuMatch) {
      if(session.role!=='admin') return resp(403,{error:"เฉพาะ Admin เท่านั้น"});
      return resp(200, await toggleUser(sql,tuMatch[1],tuMatch[2]));
    }
 
    // Cases routes
    if(method==="GET"  && (path===""||path==="/"))  {
      await sql`UPDATE user_sessions SET last_seen=NOW() WHERE token=${token} AND expires_at>NOW()`;
      return resp(200, await getCases(sql,qs));
    }
    if(method==="GET"  && path==="/stats")           return resp(200,await getStats(sql));
    if(method==="GET"  && path==="/stats/owners")   return resp(200,{stats:await getStatsByOwner(sql)});
    if(method==="GET"  && path==="/online")          return resp(200,{online:await getOnlineUsers(sql)});
    if(method==="GET"  && path==="/logs")            return resp(200,{logs:await getAllLogs(sql,qs.limit)});
    if(method==="GET"  && path==="/owners")          return resp(200,{owners:await getOwners(sql)});
    if(method==="POST" && path==="/import")          return resp(200,await bulkImport(sql,body,session));
    if(method==="POST" && (path===""||path==="/"))   return resp(200,await upsertCase(sql,body));

    const pm=path.match(/^\/([^/]+)$/);
    if(method==="PUT"  && pm)                        return resp(200,await patchCase(sql,pm[1],body,session));

    const lgm=path.match(/^\/([^/]+)\/logs$/);
    if(method==="GET"  && lgm)                       return resp(200,{logs:await getLogs(sql,lgm[1],qs.limit)});

    const npm=path.match(/^\/([^/]+)\/notes$/);
    if(method==="GET"  && npm)                       return resp(200,{notes:await getCaseNotes(sql,npm[1])});
    if(method==="POST" && npm)                       return resp(200,await addNote(sql,npm[1],body,session));

    const ndm=path.match(/^\/([^/]+)\/notes\/(\d+)$/);
    if(method==="DELETE"&&ndm)                       return resp(200,await deleteNote(sql,ndm[2]));
 
    return resp(404,{error:"Not found"});
  } catch(err) {
    console.error("Error:",err);
    return resp(500,{error:err.message});
  }
};
