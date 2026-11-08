import {reply,settings,configured,getProfile,sign,session,cookieOptions} from '../_session.js';

export async function onRequestGet({request,env}) {
  try {
    const p = await session(request,env);
    return reply(p ? {ok:true,name:p.name||p.email,role:p.role} : {ok:false},p?200:401);
  } catch(e) {
    console.error('Portal session validation:',e?.message);
    return reply({ok:false},401);
  }
}

export async function onRequestPost({request,env}) {
  const c = settings(env);
  if(!configured(c)) return reply({error:'Configuração de autenticação pendente no Cloudflare.',etapa:'configuracao'},503);
  let body;
  try {body=await request.json();}
  catch {return reply({error:'Dados inválidos.',etapa:'entrada'},400);}
  const email=String(body?.email||'').trim();
  const password=String(body?.password||'');
  if(!email||!password||email.length>254||password.length>1024)
    return reply({error:'Informe e-mail e senha.',etapa:'entrada'},400);

  let authRes;
  try {
    authRes=await fetch(c.url+'/auth/v1/token?grant_type=password',{
      method:'POST',
      headers:{apikey:c.publicKey,'Content-Type':'application/json'},
      body:JSON.stringify({email,password}),
      redirect:'follow'
    });
  } catch(e) {
    console.error('Portal diagnostic - supabase_fetch:',e?.message);
    return reply({error:'Falha na comunicação com Supabase Auth.',etapa:'supabase_fetch'},502);
  }
  if(!authRes.ok) {
    if([400,401,403,422].includes(authRes.status))
      return reply({error:'E-mail ou senha inválidos, ou conta não autorizada.',etapa:'supabase_auth',status_supabase:authRes.status},401);
    console.error('Portal diagnostic - supabase_auth_http:',authRes.status);
    return reply({error:'Supabase Auth retornou erro.',etapa:'supabase_auth_http',status_supabase:authRes.status},502);
  }

  let auth;
  try {auth=await authRes.json();}
  catch(e) {
    console.error('Portal diagnostic - supabase_json:',e?.message);
    return reply({error:'Resposta inválida do Supabase Auth.',etapa:'supabase_json'},502);
  }
  if(!auth.access_token||!auth.user?.id)
    return reply({error:'Resposta de autenticação incompleta.',etapa:'supabase_resposta'},502);

  let p;
  try {p=await getProfile(c,auth.user.id);}
  catch(e) {
    console.error('Portal diagnostic - consulta_perfil:',e?.message);
    return reply({error:'Falha ao consultar o perfil do Checklist.',etapa:'consulta_perfil'},502);
  }
  if(!p) return reply({error:'Usuário sem perfil ativo no Checklist.',etapa:'perfil_inativo'},403);

  try {
    const token=await sign({sub:p.id,exp:Date.now()+28800000},c.sessionSecret);
    return reply({ok:true,name:p.name||p.email},200,{'Set-Cookie':'modolog_portal='+token+'; '+cookieOptions});
  } catch(e) {
    console.error('Portal diagnostic - criar_sessao:',e?.message);
    return reply({error:'Falha ao criar sessão.',etapa:'criar_sessao'},502);
  }
}

export async function onRequestDelete() {
  return reply({ok:true},200,{'Set-Cookie':'modolog_portal=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'});
}
