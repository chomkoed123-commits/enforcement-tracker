// netlify/functions/cases.js
const { neon } = require("@neondatabase/serverless");

function getDb() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set");
  return neon(process.env.DATABASE_URL);
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Content-Type": "application/json",
};

function resp(s, b) { return { statusCode: s, headers: CORS, body: JSON.stringify(b) }; }

async function initDb(sql) {
  await sql`CREATE TABLE IF NOT EXISTS enforcement_cases (
    id TEXT PRIMARY KEY, sanuan TEXT, owner TEXT, hmvad TEXT, action TEXT, next_step TEXT,
    amount NUMERIC(12,2) DEFAULT 0, loan_type TEXT, work_of TEXT, asset TEXT, result TEXT,
    money_recv NUMERIC(12,2) DEFAULT 0, priority INTEGER DEFAULT 0, priority_tag TEXT,
    salary_result TEXT, bank_result TEXT, land_result TEXT, send_oa TEXT,
    attach_type TEXT, attach_detail TEXT, charge TEXT, action_status TEXT DEFAULT '',
    due_date DATE, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`;

  await sql`CREATE TABLE IF NOT EXISTS case_notes (
    id SERIAL PRIMARY KEY,
    case_id TEXT REFERENCES enforcement_cases(id) ON DELETE CASCADE,
    note_text TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`;

  await sql`CREATE TABLE IF NOT EXISTS action_logs (
    id SERIAL PRIMARY KEY,
    case_id TEXT REFERENCES enforcement_cases(id) ON DELETE CASCADE,
    changed_by TEXT,
    action_type TEXT,
    field_name TEXT,
    old_value TEXT,
    new_value TEXT,
    note TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW())`;

  return { ok: true, message: "Tables ready" };
}

async function writeLog(sql, caseId, changedBy, actionType, changes, note = "") {
  for (const [field, { old: o, new: n }] of Object.entries(changes)) {
    if (String(o ?? '') === String(n ?? '')) continue;
    await sql`INSERT INTO action_logs (case_id, changed_by, action_type, field_name, old_value, new_value, note)
      VALUES (${caseId}, ${changedBy||'user'}, ${actionType}, ${field}, ${String(o??'')}, ${String(n??'')}, ${note})`;
  }
}

async function getCases(sql, qs) {
  const { stage, result, owner, status, due, q } = qs;
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
  return await sql(`SELECT c.*, COALESCE(json_agg(json_build_object('id',n.id,'text',n.note_text,'time',n.created_at) ORDER BY n.created_at DESC) FILTER (WHERE n.id IS NOT NULL),'[]') as notes FROM enforcement_cases c LEFT JOIN case_notes n ON n.case_id=c.id ${where} GROUP BY c.id ORDER BY c.priority DESC, c.amount DESC`, params);
}

async function getLogs(sql, caseId, limit=50) {
  return await sql`SELECT * FROM action_logs WHERE case_id=${caseId} ORDER BY created_at DESC LIMIT ${parseInt(limit)}`;
}

async function getAllLogs(sql, limit=100) {
  return await sql`SELECT l.*, c.sanuan FROM action_logs l LEFT JOIN enforcement_cases c ON c.id=l.case_id ORDER BY l.created_at DESC LIMIT ${parseInt(limit)}`;
}

async function upsertCase(sql, c) {
  await sql`INSERT INTO enforcement_cases (id,sanuan,owner,hmvad,action,next_step,amount,loan_type,work_of,asset,result,money_recv,priority,priority_tag,salary_result,bank_result,land_result,send_oa,attach_type,attach_detail,charge,action_status,due_date)
    VALUES (${c.id},${c.sanuan||''},${c.owner||''},${c.hmvad||''},${c.action||''},${c.next_step||''},${c.amount||0},${c.loan_type||''},${c.work_of||''},${c.asset||''},${c.result||''},${c.money_recv||0},${c.priority||0},${c.priority_tag||'low'},${c.salary_result||''},${c.bank_result||''},${c.land_result||''},${c.send_oa||''},${c.attach_type||''},${c.attach_detail||''},${c.charge||''},${c.action_status||''},${c.due_date||null})
    ON CONFLICT (id) DO UPDATE SET sanuan=EXCLUDED.sanuan,owner=EXCLUDED.owner,hmvad=EXCLUDED.hmvad,action=EXCLUDED.action,next_step=EXCLUDED.next_step,amount=EXCLUDED.amount,loan_type=EXCLUDED.loan_type,work_of=EXCLUDED.work_of,asset=EXCLUDED.asset,result=EXCLUDED.result,money_recv=EXCLUDED.money_recv,priority=EXCLUDED.priority,priority_tag=EXCLUDED.priority_tag,salary_result=EXCLUDED.salary_result,bank_result=EXCLUDED.bank_result,land_result=EXCLUDED.land_result,send_oa=EXCLUDED.send_oa,attach_type=EXCLUDED.attach_type,attach_detail=EXCLUDED.attach_detail,charge=EXCLUDED.charge,action_status=EXCLUDED.action_status,due_date=EXCLUDED.due_date,updated_at=NOW()`;
  return { ok: true, id: c.id };
}

async function patchCase(sql, id, body) {
  const [before] = await sql`SELECT * FROM enforcement_cases WHERE id=${id}`;
  if (!before) return { ok: false, error: "Case not found" };
  const fields=[], vals=[], changes={};
  let i=1;
  const allowed={action_status:"action_status",due_date:"due_date",action:"action",hmvad:"hmvad",result:"result",money_recv:"money_recv",amount:"amount"};
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
  await writeLog(sql, id, body.changed_by||body.owner||'user', 'EDIT', changes, body.note||'');
  return { ok: true };
}

async function addNote(sql, caseId, body) {
  const [row] = await sql`INSERT INTO case_notes (case_id,note_text) VALUES (${caseId},${body.text}) RETURNING id,note_text,created_at`;
  await writeLog(sql, caseId, body.changed_by||'user', 'NOTE', { note_text:{old:'',new:body.text} }, body.text);
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

async function getStats(sql) {
  const [row] = await sql`SELECT COUNT(*)::int AS total, SUM(amount)::numeric AS total_claimed, SUM(money_recv)::numeric AS total_recv, COUNT(*) FILTER(WHERE asset='มีทรัพย์สิน')::int AS has_asset, COUNT(*) FILTER(WHERE result='ได้เงิน')::int AS got_money, COUNT(*) FILTER(WHERE result LIKE '%ไม่ได้เงิน%')::int AS no_money, COUNT(*) FILTER(WHERE result='รอผล')::int AS pending, COUNT(*) FILTER(WHERE due_date<CURRENT_DATE AND action_status!='done')::int AS overdue, COUNT(*) FILTER(WHERE action_status='done')::int AS done_count FROM enforcement_cases`;
  const r=parseFloat(row.total_recv)||0, c=parseFloat(row.total_claimed)||1;
  return { ...row, recovery_rate: Math.round(r/c*1000)/10 };
}

exports.handler = async (event) => {
  if (event.httpMethod==="OPTIONS") return {statusCode:200,headers:CORS,body:""};
  let sql;
  try { sql=getDb(); } catch(e) { return resp(500,{error:e.message}); }
  const method=event.httpMethod;
  const path=(event.path||"").replace(/^\/\.netlify\/functions\/cases/,"");
  const qs=event.queryStringParameters||{};
  let body={};
  try { if(event.body) body=JSON.parse(event.body); } catch(_){}
  try {
    if(method==="GET"  && (path===""||path==="/"))  return resp(200,{cases:await getCases(sql,qs)});
    if(method==="GET"  && path==="/stats")           return resp(200,await getStats(sql));
    if(method==="GET"  && path==="/logs")            return resp(200,{logs:await getAllLogs(sql,qs.limit)});
    if(method==="POST" && path==="/init")            return resp(200,await initDb(sql));
    if(method==="POST" && path==="/seed")            return resp(200,await bulkSeed(sql,body));
    if(method==="POST" && (path===""||path==="/"))   return resp(200,await upsertCase(sql,body));
    const pm=path.match(/^\/([^/]+)$/);
    if(method==="PUT"  && pm)                        return resp(200,await patchCase(sql,pm[1],body));
    const lgm=path.match(/^\/([^/]+)\/logs$/);
    if(method==="GET"  && lgm)                       return resp(200,{logs:await getLogs(sql,lgm[1],qs.limit)});
    const npm=path.match(/^\/([^/]+)\/notes$/);
    if(method==="POST" && npm)                       return resp(200,await addNote(sql,npm[1],body));
    const ndm=path.match(/^\/([^/]+)\/notes\/(\d+)$/);
    if(method==="DELETE"&&ndm)                       return resp(200,await deleteNote(sql,ndm[2]));
    return resp(404,{error:"Not found"});
  } catch(err) {
    console.error("Error:",err);
    return resp(500,{error:err.message});
  }
};
