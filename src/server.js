import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import {createClient} from '@supabase/supabase-js';
import {Server as SocketServer} from 'socket.io';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(compression());
app.use(express.json({limit:'32kb'}));
app.use(cookieParser());

const apiLimiter = rateLimit({windowMs:60_000, limit:120, standardHeaders:'draft-8', legacyHeaders:false});
const loginLimiter = rateLimit({windowMs:15*60_000, limit:8, standardHeaders:'draft-8', legacyHeaders:false, message:{ok:false,error:'Too many login attempts. Try again later.'}});
app.use('/api/', apiLimiter);

const url = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const db = url && serviceKey ? createClient(url, serviceKey, {auth:{persistSession:false}}) : null;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const COOKIE_SECURE = process.env.NODE_ENV === 'production';
const ADMIN_TTL_MS = 8*60*60*1000;
const ADMIN_SESSION_TABLE = 'admin_sessions';
const SESSION_TTL_MS = 24*60*60*1000;
const ENGINE_BASE_URL = (process.env.ENGINE_BASE_URL || '').replace(/\/$/,'');

function requireDb(res){if(!db){res.status(503).json({ok:false,error:'Database is not configured'});return false}return true}
function sha(v){return crypto.createHash('sha256').update(String(v)).digest('hex')}
function randomToken(bytes=32){return crypto.randomBytes(bytes).toString('hex')}
function randomKey(){return 'NYA-'+crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{1,4}/g).join('-')}
function keyHash(key){return sha(String(key).trim().toUpperCase())}
function safeEqual(a,b){const aa=Buffer.from(String(a));const bb=Buffer.from(String(b));return aa.length===bb.length && crypto.timingSafeEqual(aa,bb)}
function adminCookieToken(req){return req.cookies.ny_admin || ''}
function adminSig(token){return sha(token+ADMIN_SECRET)}
function csrfFor(token){return sha('csrf:'+token+ADMIN_SECRET).slice(0,48)}
function setAdmin(res,token){
  res.cookie('ny_admin',token,{httpOnly:true,sameSite:'strict',secure:COOKIE_SECURE,maxAge:ADMIN_TTL_MS,path:'/'});
  res.cookie('ny_admin_sig',adminSig(token),{httpOnly:true,sameSite:'strict',secure:COOKIE_SECURE,maxAge:ADMIN_TTL_MS,path:'/'});
  res.cookie('ny_admin_csrf',csrfFor(token),{httpOnly:false,sameSite:'strict',secure:COOKIE_SECURE,maxAge:ADMIN_TTL_MS,path:'/'});
}
async function isAdmin(req){
  if(!ADMIN_SECRET || !db)return false;
  const token=adminCookieToken(req); const sig=req.cookies.ny_admin_sig || '';
  if(!token || !sig || !safeEqual(sig,adminSig(token)))return false;
  const {data,error}=await db.from(ADMIN_SESSION_TABLE).select('id,expires_at,revoked_at').eq('token_hash',sha(token)).maybeSingle();
  if(error || !data || data.revoked_at || new Date(data.expires_at)<=new Date())return false;
  return true;
}
function checkCsrf(req){
  const token=adminCookieToken(req); const supplied=req.get('x-csrf-token') || '';
  return Boolean(token && supplied && safeEqual(supplied,csrfFor(token)));
}
async function authAdmin(req,res,next){if(!(await isAdmin(req)))return res.status(401).json({ok:false,error:'Admin authentication required'});next()}
function writeGuard(req,res,next){if(!checkCsrf(req))return res.status(403).json({ok:false,error:'CSRF validation failed'});next()}
function validPassword(password){
  if(!ADMIN_PASSWORD_HASH || !password || password.length>256)return false;
  try{return bcrypt.compareSync(password,ADMIN_PASSWORD_HASH)}catch{return false}
}
function publicKey(k){return {id:k.id,status:k.status,expires_at:k.expires_at,max_devices:k.max_devices,bound_phone:k.bound_phone,bound_platform:k.bound_platform,device_id:k.device_id,notes:k.notes,created_at:k.created_at,updated_at:k.updated_at,last_used_at:k.last_used_at,key_last4:k.key_last4}}
async function audit(action,target,details={}){if(!db)return;await db.from('admin_audit_logs').insert({action,target:String(target??''),details})}
async function proxyEngine(pathname,req,res){
  if(!ENGINE_BASE_URL)return res.status(503).json({ok:false,error:'Betting engine is not connected. Set ENGINE_BASE_URL to the original backend.'});
  try{
    const headers={'content-type':'application/json'};
    const r=await fetch(ENGINE_BASE_URL+pathname,{method:req.method,headers,body:['GET','HEAD'].includes(req.method)?undefined:JSON.stringify(req.body||{})});
    const text=await r.text(); res.status(r.status).type(r.headers.get('content-type')||'application/json').send(text);
  }catch(e){res.status(502).json({ok:false,error:'Engine upstream unavailable'})}
}

app.get('/health',(req,res)=>res.json({ok:true,name:'NY AUTOBET',version:'2.0.0',db:!!db,engineConnected:!!ENGINE_BASE_URL}));
app.get('/api/config',(req,res)=>res.json({ok:true,brand:'NY AUTOBET',engineConnected:!!ENGINE_BASE_URL}));

app.post('/api/admin/login',loginLimiter,async(req,res)=>{
  const {password}=req.body||{};
  if(!ADMIN_SECRET || !ADMIN_PASSWORD_HASH || !validPassword(password))return res.status(401).json({ok:false,error:'Invalid admin credentials'});
  if(!db)return res.status(503).json({ok:false,error:'Database is not configured'});
  const token=randomToken();
  const expires=new Date(Date.now()+ADMIN_TTL_MS).toISOString();
  const {error}=await db.from(ADMIN_SESSION_TABLE).insert({token_hash:sha(token),expires_at:expires});
  if(error)return res.status(500).json({ok:false,error:'Could not create admin session'});
  setAdmin(res,token);
  await audit('admin.login','admin',{});
  res.json({ok:true,csrf:csrfFor(token),expiresAt:expires});
});
app.get('/api/admin/me',authAdmin,(req,res)=>res.json({ok:true,admin:true,csrf:csrfFor(adminCookieToken(req))}));
app.post('/api/admin/logout',authAdmin,writeGuard,async(req,res)=>{if(db)await db.from(ADMIN_SESSION_TABLE).update({revoked_at:new Date().toISOString()}).eq('token_hash',sha(adminCookieToken(req)));res.clearCookie('ny_admin',{path:'/'});res.clearCookie('ny_admin_sig',{path:'/'});res.clearCookie('ny_admin_csrf',{path:'/'});res.json({ok:true})});

app.get('/api/admin/stats',authAdmin,async(req,res)=>{
  if(!requireDb(res))return;
  const [{count:total},{count:active},{count:sessions},{count:audits}] = await Promise.all([
    db.from('license_keys').select('*',{count:'exact',head:true}),
    db.from('license_keys').select('*',{count:'exact',head:true}).eq('status','active'),
    db.from('license_sessions').select('*',{count:'exact',head:true}).is('stopped_at',null),
    db.from('admin_audit_logs').select('*',{count:'exact',head:true})
  ]);
  res.json({ok:true,stats:{total:total||0,active:active||0,sessions:sessions||0,audits:audits||0,engineConnected:!!ENGINE_BASE_URL}});
});

app.post('/api/admin/keys',authAdmin,writeGuard,async(req,res)=>{
  if(!requireDb(res))return;
  const {expires_at=null,max_devices=1,notes=''}=req.body||{};
  const md=Math.max(1,Math.min(50,Number(max_devices)||1));
  const key=randomKey();
  const {data,error}=await db.from('license_keys').insert({key_hash:keyHash(key),key_last4:key.slice(-4),expires_at:expires_at||null,max_devices:md,notes:String(notes).slice(0,500)||null}).select().single();
  if(error)return res.status(500).json({ok:false,error:error.message});
  await audit('key.create',data.id,{key_last4:data.key_last4,max_devices:md,expires_at:data.expires_at});
  res.json({ok:true,key,license:publicKey(data),message:'Copy this key now. The full key is not stored in plaintext.'});
});
app.get('/api/admin/keys',authAdmin,async(req,res)=>{
  if(!requireDb(res))return;
  const q=String(req.query.q||'').trim();
  let query=db.from('license_keys').select('*').order('created_at',{ascending:false}).limit(500);
  if(q)query=query.or(`key_last4.ilike.%${q.slice(0,20)}%,notes.ilike.%${q.slice(0,20)}%,status.eq.${q}`);
  const {data,error}=await query;if(error)return res.status(500).json({ok:false,error:error.message});
  res.json({ok:true,keys:(data||[]).map(publicKey)});
});
app.patch('/api/admin/keys/:id',authAdmin,writeGuard,async(req,res)=>{
  if(!requireDb(res))return;
  const patch={};for(const k of ['status','expires_at','max_devices','notes'])if(k in req.body)patch[k]=req.body[k];
  if('status'in patch && !['active','disabled','expired'].includes(patch.status))return res.status(400).json({ok:false,error:'Invalid status'});
  if('max_devices'in patch)patch.max_devices=Math.max(1,Math.min(50,Number(patch.max_devices)||1));
  patch.updated_at=new Date().toISOString();
  const {data,error}=await db.from('license_keys').update(patch).eq('id',req.params.id).select().single();
  if(error)return res.status(500).json({ok:false,error:error.message});
  await audit('key.update',req.params.id,patch);res.json({ok:true,key:publicKey(data)});
});
app.delete('/api/admin/keys/:id',authAdmin,writeGuard,async(req,res)=>{
  if(!requireDb(res))return;
  const {error}=await db.from('license_keys').delete().eq('id',req.params.id);if(error)return res.status(500).json({ok:false,error:error.message});
  await audit('key.delete',req.params.id,{});res.json({ok:true});
});

async function checkKey(req,res){
  if(!requireDb(res))return;
  const {key,phone,platform,deviceId}=req.body||{};
  if(!key)return res.status(400).json({ok:false,valid:false,error:'License key required'});
  const normalized=String(key).trim().toUpperCase();
  const {data,error}=await db.from('license_keys').select('*').eq('key_hash',keyHash(normalized)).maybeSingle();
  if(error)return res.status(500).json({ok:false,valid:false,error:'License lookup failed'});
  if(!data)return res.status(404).json({ok:false,valid:false,error:'Invalid license key'});
  if(data.status!=='active')return res.status(403).json({ok:false,valid:false,error:'License is disabled'});
  if(data.expires_at && new Date(data.expires_at)<=new Date()){await db.from('license_keys').update({status:'expired'}).eq('id',data.id);return res.status(403).json({ok:false,valid:false,error:'License expired'})}
  if(data.device_id && data.device_id!==deviceId)return res.status(403).json({ok:false,valid:false,error:'License is bound to another device'});
  const {count}=await db.from('license_sessions').select('*',{count:'exact',head:true}).eq('license_id',data.id).is('stopped_at',null).gt('last_seen_at',new Date(Date.now()-SESSION_TTL_MS).toISOString());
  if(!data.device_id && deviceId && (count||0)>=data.max_devices)return res.status(403).json({ok:false,valid:false,error:'Device/session limit reached'});
  const token=randomToken();
  await db.from('license_sessions').insert({license_id:data.id,session_token_hash:sha(token),phone:phone||null,platform:platform||null,device_id:deviceId||null,ip_hash:sha(req.ip||'')});
  await db.from('license_keys').update({last_used_at:new Date().toISOString(),bound_phone:phone||data.bound_phone,bound_platform:platform||data.bound_platform,device_id:deviceId||data.device_id}).eq('id',data.id);
  res.json({ok:true,valid:true,sessionId:token,boundPhone:phone||data.bound_phone,boundPlatform:platform||data.bound_platform,isDefault:false,expiresAt:data.expires_at});
}
app.post('/api/keys/check',checkKey);app.post('/api/keys/validate',checkKey);app.post('/api/keys/login-check',checkKey);app.post('/api/keys/bind',checkKey);
app.get('/api/platforms',async(req,res)=>proxyEngine('/api/platforms',req,res));
app.all('/api/platform/:platform/*splat',async(req,res)=>proxyEngine('/api/platform/'+encodeURIComponent(req.params.platform)+'/'+req.params.splat,req,res));
app.post('/api/keys/session/balance',async(req,res)=>proxyEngine('/api/keys/session/balance',req,res));
app.post('/api/keys/session/stop',async(req,res)=>{
  if(!requireDb(res))return;
  const {sessionId}=req.body||{};if(!sessionId)return res.status(400).json({ok:false,error:'sessionId required'});
  const {error}=await db.from('license_sessions').update({stopped_at:new Date().toISOString()}).eq('session_token_hash',sha(sessionId));
  if(error)return res.status(500).json({ok:false,error:'Could not stop session'});res.json({ok:true});
});

app.get('/api/admin/sessions',authAdmin,async(req,res)=>{if(!requireDb(res))return;const {data,error}=await db.from('license_sessions').select('id,license_id,phone,platform,device_id,created_at,last_seen_at,stopped_at').order('created_at',{ascending:false}).limit(300);if(error)return res.status(500).json({ok:false,error:error.message});res.json({ok:true,sessions:data||[]})});
app.post('/api/admin/sessions/:id/stop',authAdmin,writeGuard,async(req,res)=>{if(!requireDb(res))return;const {error}=await db.from('license_sessions').update({stopped_at:new Date().toISOString()}).eq('id',req.params.id);if(error)return res.status(500).json({ok:false,error:error.message});await audit('session.stop',req.params.id,{});res.json({ok:true})});
app.get('/api/admin/audit',authAdmin,async(req,res)=>{if(!requireDb(res))return;const {data,error}=await db.from('admin_audit_logs').select('*').order('created_at',{ascending:false}).limit(200);if(error)return res.status(500).json({ok:false,error:error.message});res.json({ok:true,logs:data||[]})});

const httpServer=(await import('node:http')).createServer(app);
const io=new SocketServer(httpServer,{cors:{origin:true,credentials:true}});
const ENGINE_EVENTS = new Set([
  'auth','switchView','start','stop','addLayer2','startLayer','stopLayer','resetStats',
  'setLevels','setLayerLevels','setWatch','setTargetLevelBet','setLevelJump','setCompounding',
  'setManualFollower','manualPrediction','setGameMode','getBetRecord','exportHistory',
  'setFormula','setLayerFormula','nexusWarmup','nexusPredict','removeLayer2','getAccounts'
]);
const ENGINE_OUT_EVENTS = new Set([
  'state','accountList','accountRemoved','countdown','manualPeriod','manualOverview','manualLog',
  'newDraw','log','logs','toast','betStatus','maxLevel','betRecord','exportHistoryProgress',
  'exportHistoryResult','reauth','nexusWarmupProgress','nexusWarmupDone','nexusDecision','reauth'
]);

async function validLicenseSession(sessionId){
  if(!db || !sessionId)return null;
  const {data}=await db.from('license_sessions').select('id,license_id,stopped_at,last_seen_at').eq('session_token_hash',sha(sessionId)).maybeSingle();
  if(!data || data.stopped_at || new Date(data.last_seen_at)<new Date(Date.now()-SESSION_TTL_MS))return null;
  await db.from('license_sessions').update({last_seen_at:new Date().toISOString()}).eq('id',data.id);
  return data;
}

io.on('connection',socket=>{
  let upstream=null;
  let sessionId=null;
  const send=(event,payload)=>{ if(socket.connected) socket.emit(event,payload); };

  socket.on('auth',async(payload={})=>{
    const sid=payload.sessionId || sessionId;
    const session=await validLicenseSession(sid);
    if(!session){send('authError',{msg:'License session expired or stopped'});return;}
    sessionId=sid;
    if(!ENGINE_BASE_URL){send('state',{engineReady:false,message:'License authenticated. Configure ENGINE_BASE_URL to connect the original engine.'});return;}
    if(!upstream){
      try{
        const {io:engineIo}=await import('socket.io-client');
        upstream=engineIo(ENGINE_BASE_URL,{transports:['websocket','polling'],timeout:10000,reconnection:true});
        upstream.on('connect_error',err=>send('authError',{msg:'Engine connection failed'}));
        upstream.on('disconnect',()=>send('toast',{title:'Engine',msg:'Engine connection lost',type:'error'}));
        for(const ev of ENGINE_OUT_EVENTS) upstream.on(ev,(data)=>send(ev,data));
      }catch(e){send('authError',{msg:'Engine bridge unavailable'});return;}
    }
    const forwarded={...payload};delete forwarded.sessionId;
    upstream.emit('auth',forwarded);
  });

  for(const event of ENGINE_EVENTS){
    socket.on(event,async(...args)=>{
      if(event==='auth')return;
      const session=await validLicenseSession(sessionId);
      if(!session){send('authError',{msg:'License session expired or stopped'});return;}
      if(event==='stop' && db) await db.from('license_sessions').update({last_seen_at:new Date().toISOString()}).eq('id',session.id);
      if(upstream?.connected) upstream.emit(event,...args);
    });
  }

  socket.on('disconnect',()=>{try{upstream?.disconnect()}catch{};upstream=null});
});

app.use(express.static(path.join(__dirname,'../public'),{extensions:['html']}));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'../public/admin.html')));
app.use((req,res)=>res.status(404).json({ok:false,error:'Not found'}));
const port=Number(process.env.PORT||3000);httpServer.listen(port,'0.0.0.0',()=>console.log(`[NY AUTOBET] listening on ${port}`));
