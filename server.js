const express=require("express"), helmet=require("helmet"), rateLimit=require("express-rate-limit");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), Database=require("better-sqlite3");
const crypto=require("crypto"), path=require("path");
const app=express(), db=new Database(process.env.DB_FILE||"yemen-vip.sqlite");
const PORT=process.env.PORT||3000, JWT_SECRET=process.env.JWT_SECRET, ADMIN_PASSWORD_HASH=process.env.ADMIN_PASSWORD_HASH;
if(!JWT_SECRET||!ADMIN_PASSWORD_HASH){console.error("Set JWT_SECRET and ADMIN_PASSWORD_HASH in environment.");process.exit(1)}
app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:"20kb"}));
app.use("/api",rateLimit({windowMs:15*60*1000,max:120,standardHeaders:true,legacyHeaders:false}));
db.exec(`CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,code_hash TEXT UNIQUE NOT NULL,status TEXT NOT NULL DEFAULT 'active',expires_at TEXT NOT NULL,created_at TEXT NOT NULL);`);
const hash=s=>crypto.createHash("sha256").update(s).digest("hex");
const makeToken=payload=>jwt.sign(payload,JWT_SECRET,{expiresIn:"12h"});
function auth(req,res,next){try{const p=jwt.verify((req.headers.authorization||"").replace(/^Bearer\s+/i,""),JWT_SECRET);if(p.role!=="subscriber")throw Error();const s=db.prepare("SELECT * FROM subscriptions WHERE id=?").get(p.id);if(!s||s.status!=="active"||Date.parse(s.expires_at)<=Date.now())return res.status(401).json({error:"الاشتراك غير فعال أو منتهي"});req.sub=s;next()}catch{return res.status(401).json({error:"يلزم تسجيل الدخول بكود فعال"})}}
function admin(req,res,next){try{const p=jwt.verify(req.headers["x-admin-token"],JWT_SECRET);if(p.role!=="admin")throw Error();next()}catch{return res.status(401).json({error:"صلاحية الإدارة غير صالحة"})}}
app.post("/api/login",(req,res)=>{const code=String(req.body.code||"").trim();if(code.length<10||code.length>100)return res.status(400).json({error:"كود الاشتراك غير صحيح"});const s=db.prepare("SELECT * FROM subscriptions WHERE code_hash=?").get(hash(code));if(!s||s.status!=="active")return res.status(401).json({error:"كود غير صحيح أو موقوف"});if(Date.parse(s.expires_at)<=Date.now())return res.status(401).json({error:"انتهت صلاحية الاشتراك"});res.json({token:makeToken({role:"subscriber",id:s.id}),expiresAt:s.expires_at})});
app.get("/api/me",auth,(req,res)=>res.json({name:req.sub.name,expiresAt:req.sub.expires_at}));
app.post("/api/admin/login",async(req,res)=>{const ok=await bcrypt.compare(String(req.body.password||""),process.env.ADMIN_PASSWORD_HASH);if(!ok)return res.status(401).json({error:"كلمة مرور المطور غير صحيحة"});res.json({token:makeToken({role:"admin"})})});
app.get("/api/admin/subscriptions",admin,(req,res)=>res.json({subscriptions:db.prepare("SELECT id,name,status,expires_at,created_at FROM subscriptions ORDER BY id DESC").all()}));
app.post("/api/admin/subscriptions",admin,(req,res)=>{const name=String(req.body.name||"مشترك").slice(0,80),days=Number(req.body.days);if(!Number.isInteger(days)||days<1||days>3650)return res.status(400).json({error:"المدة يجب أن تكون بين يوم و3650 يوماً"});const code="YSP-"+crypto.randomBytes(18).toString("hex").toUpperCase(),expires=new Date(Date.now()+days*86400000).toISOString();const result=db.prepare("INSERT INTO subscriptions(name,code_hash,expires_at,created_at) VALUES(?,?,?,?)").run(name,hash(code),expires,new Date().toISOString());res.json({id:result.lastInsertRowid,code,expiresAt:expires})});
app.post("/api/admin/subscriptions/:id/disable",admin,(req,res)=>{const r=db.prepare("UPDATE subscriptions SET status='disabled' WHERE id=?").run(Number(req.params.id));if(!r.changes)return res.status(404).json({error:"المشترك غير موجود"});res.json({ok:true})});
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`YEMEN SCRIPT VIP running on http://localhost:${PORT}`));
