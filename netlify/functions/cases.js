// netlify/functions/cases.js
// API handler สำหรับ CRUD operations ทั้งหมด

const { neon } = require("@neondatabase/serverless");

function getDb() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not set");
  }
  return neon(process.env.DATABASE_URL);
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Content-Type": "application/json",
};

function resp(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body) };
}

// ── สร้างตาราง (รันครั้งแรกเท่านั้น) ──────────────────────────────────────
async function initDb(sql) {
  await sql`
    CREATE TABLE IF NOT EXISTS enforcement_cases (
      id            TEXT PRIMARY KEY,
      sanuan        TEXT,
      owner         TEXT,
      hmvad         TEXT,
      action        TEXT,
      next_step     TEXT,
      amount        NUMERIC(12,2) DEFAULT 0,
      loan_type     TEXT,
      work_of       TEXT,
      asset         TEXT,
      result        TEXT,
      money_recv    NUMERIC(12,2) DEFAULT 0,
      priority      INTEGER DEFAULT 0,
      priority_tag  TEXT,
      salary_result TEXT,
      bank_result   TEXT,
      land_result   TEXT,
      send_oa       TEXT,
      attach_type   TEXT,
      attach_detail TEXT,
      charge        TEXT,
      action_status TEXT DEFAULT '',
      due_date      DATE,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS case_notes (
      id         SERIAL PRIMARY KEY,
      case_id    TEXT REFERENCES enforcement_cases(id) ON DELETE CASCADE,
      note_text  TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
  return { ok: true, message: "Tables ready" };
}

// ── GET /cases ─────────────────────────────────────────────────────────────
async function getCases(sql, queryParams) {
  const { stage, result, owner, status, due, q } = queryParams;

  let conditions = [];
  let params = [];
  let idx = 1;

  if (stage) {
    conditions.push(`hmvad LIKE $${idx}`);
    params.push(stage + "%");
    idx++;
  }
  if (result) {
    conditions.push(`result = $${idx}`);
    params.push(result);
    idx++;
  }
  if (owner) {
    conditions.push(`owner = $${idx}`);
    params.push(owner);
    idx++;
  }
  if (status) {
    conditions.push(`action_status = $${idx}`);
    params.push(status);
    idx++;
  }
  if (q) {
    conditions.push(
      `(id ILIKE $${idx} OR sanuan ILIKE $${idx} OR owner ILIKE $${idx} OR action ILIKE $${idx})`
    );
    params.push("%" + q + "%");
    idx++;
  }
  if (due === "overdue") {
    conditions.push(`due_date < CURRENT_DATE AND action_status != 'done'`);
  } else if (due === "today") {
    conditions.push(`due_date = CURRENT_DATE`);
  } else if (due === "soon") {
    conditions.push(
      `due_date >= CURRENT_DATE AND due_date <= CURRENT_DATE + INTERVAL '7 days'`
    );
  } else if (due === "has_due") {
    conditions.push(`due_date IS NOT NULL`);
  }

  const where =
    conditions.length > 0 ? "WHERE " + conditions.join(" AND ") : "";
  const query = `
    SELECT c.*,
      COALESCE(
        json_agg(
          json_build_object('id', n.id, 'text', n.note_text, 'time', n.created_at)
          ORDER BY n.created_at DESC
        ) FILTER (WHERE n.id IS NOT NULL),
        '[]'
      ) as notes
    FROM enforcement_cases c
    LEFT JOIN case_notes n ON n.case_id = c.id
    ${where}
    GROUP BY c.id
    ORDER BY c.priority DESC, c.amount DESC
  `;

  const rows = await sql(query, params);
  return rows;
}

// ── POST /cases (upsert) ────────────────────────────────────────────────────
async function upsertCase(sql, body) {
  const c = body;
  await sql`
    INSERT INTO enforcement_cases (
      id, sanuan, owner, hmvad, action, next_step, amount, loan_type,
      work_of, asset, result, money_recv, priority, priority_tag,
      salary_result, bank_result, land_result, send_oa, attach_type,
      attach_detail, charge, action_status, due_date
    ) VALUES (
      ${c.id}, ${c.sanuan||''}, ${c.owner||''}, ${c.hmvad||''},
      ${c.action||''}, ${c.next_step||''}, ${c.amount||0}, ${c.loan_type||''},
      ${c.work_of||''}, ${c.asset||''}, ${c.result||''}, ${c.money_recv||0},
      ${c.priority||0}, ${c.priority_tag||'low'}, ${c.salary_result||''},
      ${c.bank_result||''}, ${c.land_result||''}, ${c.send_oa||''},
      ${c.attach_type||''}, ${c.attach_detail||''}, ${c.charge||''},
      ${c.action_status||''}, ${c.due_date||null}
    )
    ON CONFLICT (id) DO UPDATE SET
      sanuan        = EXCLUDED.sanuan,
      owner         = EXCLUDED.owner,
      hmvad         = EXCLUDED.hmvad,
      action        = EXCLUDED.action,
      next_step     = EXCLUDED.next_step,
      amount        = EXCLUDED.amount,
      loan_type     = EXCLUDED.loan_type,
      work_of       = EXCLUDED.work_of,
      asset         = EXCLUDED.asset,
      result        = EXCLUDED.result,
      money_recv    = EXCLUDED.money_recv,
      priority      = EXCLUDED.priority,
      priority_tag  = EXCLUDED.priority_tag,
      salary_result = EXCLUDED.salary_result,
      bank_result   = EXCLUDED.bank_result,
      land_result   = EXCLUDED.land_result,
      send_oa       = EXCLUDED.send_oa,
      attach_type   = EXCLUDED.attach_type,
      attach_detail = EXCLUDED.attach_detail,
      charge        = EXCLUDED.charge,
      action_status = EXCLUDED.action_status,
      due_date      = EXCLUDED.due_date,
      updated_at    = NOW()
  `;
  return { ok: true, id: c.id };
}

// ── PUT /cases/:id (patch สถานะ/due/action) ────────────────────────────────
async function patchCase(sql, id, body) {
  const fields = [];
  const vals = [];
  let i = 1;

  const allowed = {
    action_status: "action_status",
    due_date: "due_date",
    action: "action",
    hmvad: "hmvad",
    result: "result",
    money_recv: "money_recv",
    amount: "amount",
  };

  for (const [k, col] of Object.entries(allowed)) {
    if (body[k] !== undefined) {
      fields.push(`${col} = $${i}`);
      vals.push(body[k] === "" ? null : body[k]);
      i++;
    }
  }

  if (fields.length === 0) return { ok: false, error: "No fields to update" };

  fields.push(`updated_at = NOW()`);
  vals.push(id);

  await sql(
    `UPDATE enforcement_cases SET ${fields.join(", ")} WHERE id = $${i}`,
    vals
  );
  return { ok: true };
}

// ── POST /cases/:id/notes ───────────────────────────────────────────────────
async function addNote(sql, caseId, body) {
  const [row] = await sql`
    INSERT INTO case_notes (case_id, note_text)
    VALUES (${caseId}, ${body.text})
    RETURNING id, note_text, created_at
  `;
  return row;
}

// ── DELETE /cases/:id/notes/:noteId ────────────────────────────────────────
async function deleteNote(sql, noteId) {
  await sql`DELETE FROM case_notes WHERE id = ${parseInt(noteId)}`;
  return { ok: true };
}

// ── BULK SEED (import จาก Excel data ครั้งแรก) ─────────────────────────────
async function bulkSeed(sql, body) {
  const { cases } = body;
  if (!Array.isArray(cases) || cases.length === 0) {
    return { ok: false, error: "No cases provided" };
  }

  let count = 0;
  for (const c of cases) {
    await upsertCase(sql, c);
    count++;
  }
  return { ok: true, inserted: count };
}

// ── GET /stats ──────────────────────────────────────────────────────────────
async function getStats(sql) {
  const [row] = await sql`
    SELECT
      COUNT(*)::int                                          AS total,
      SUM(amount)::numeric                                   AS total_claimed,
      SUM(money_recv)::numeric                               AS total_recv,
      COUNT(*) FILTER (WHERE asset = 'มีทรัพย์สิน')::int    AS has_asset,
      COUNT(*) FILTER (WHERE result = 'ได้เงิน')::int        AS got_money,
      COUNT(*) FILTER (WHERE result LIKE '%ไม่ได้เงิน%')::int AS no_money,
      COUNT(*) FILTER (WHERE result = 'รอผล')::int           AS pending,
      COUNT(*) FILTER (
        WHERE due_date < CURRENT_DATE AND action_status != 'done'
      )::int                                                 AS overdue,
      COUNT(*) FILTER (WHERE action_status = 'done')::int   AS done_count
    FROM enforcement_cases
  `;
  const r = parseFloat(row.total_recv) || 0;
  const c = parseFloat(row.total_claimed) || 1;
  return { ...row, recovery_rate: Math.round((r / c) * 1000) / 10 };
}

// ── MAIN HANDLER ────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }

  let sql;
  try {
    sql = getDb();
  } catch (e) {
    return resp(500, { error: e.message });
  }

  const method = event.httpMethod;
  const path = (event.path || "").replace(/^\/\.netlify\/functions\/cases/, "");
  const qs = event.queryStringParameters || {};
  let body = {};

  try {
    if (event.body) body = JSON.parse(event.body);
  } catch (_) {}

  try {
    // GET /
    if (method === "GET" && (path === "" || path === "/")) {
      const cases = await getCases(sql, qs);
      return resp(200, { cases });
    }

    // GET /stats
    if (method === "GET" && path === "/stats") {
      const stats = await getStats(sql);
      return resp(200, stats);
    }

    // POST /init  (สร้างตารางครั้งแรก)
    if (method === "POST" && path === "/init") {
      const result = await initDb(sql);
      return resp(200, result);
    }

    // POST /seed  (import bulk data)
    if (method === "POST" && path === "/seed") {
      const result = await bulkSeed(sql, body);
      return resp(200, result);
    }

    // POST /  (upsert single case)
    if (method === "POST" && (path === "" || path === "/")) {
      const result = await upsertCase(sql, body);
      return resp(200, result);
    }

    // PUT /:id  (patch fields)
    const putMatch = path.match(/^\/([^/]+)$/);
    if (method === "PUT" && putMatch) {
      const result = await patchCase(sql, putMatch[1], body);
      return resp(200, result);
    }

    // POST /:id/notes
    const notePostMatch = path.match(/^\/([^/]+)\/notes$/);
    if (method === "POST" && notePostMatch) {
      const result = await addNote(sql, notePostMatch[1], body);
      return resp(200, result);
    }

    // DELETE /:id/notes/:noteId
    const noteDelMatch = path.match(/^\/([^/]+)\/notes\/(\d+)$/);
    if (method === "DELETE" && noteDelMatch) {
      const result = await deleteNote(sql, noteDelMatch[2]);
      return resp(200, result);
    }

    return resp(404, { error: "Not found" });
  } catch (err) {
    console.error("Function error:", err);
    return resp(500, { error: err.message });
  }
};
