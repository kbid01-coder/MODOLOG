import {reply,settings,configured,getProfile,sign,session,cookieOptions} from '../_session.js';
export async function onRequestGet({request,env}){try{const p=await session(request,env);return reply(p?{ok:true,name:p.name||p.email,role:p.role}:{ok:false},p?200:401);}catch(e){console.error('Portal session validation:',e?.message);return reply({ok:false},401);}}
export async function onRequestPost({request,env}){
 const c=settings(env);
 if(!configured(c))return reply({error:'Configuração de autenticação pendente no Cloudflare.'},503);
 let body;try{body=await request.json();}catch{return reply({error:'Dados inválidos.'},400);}
 const email=String(body?.email||'').trim(),password=String(body?.password||'');
 if(!email||!password||email.length>254||password.length>1024)return reply({error:'Informe e-mail e senha.'},400);
 try{
  const authRes=await fetch(c.url+'/auth/v1/token?grant_type=password',{method:'POST',headers:{apikey:c.publicKey,'Content-Type':'application/json'},body:JSON.stringify({email,password}),redirect:'error'});
  if(!authRes.ok){if([400,401,403,422].includes(authRes.status))return reply({error:'E-mail ou senha inválidos, ou conta não autorizada.'},401);console.error('Supabase auth HTTP:',authRes.status);return reply({error:'Serviço de autenticação indisponível. Tente novamente.'},502);}
  const auth=await authRes.json();if(!auth.access_token||!auth.user?.id)return reply({error:'Resposta de autenticação inválida.'},502);
  const p=await getProfile(c,auth.user.id);
  if(!p)return reply({error:'Usuário sem perfil ativo no Checklist.'},403);
  const token=await sign({sub:p.id,exp:Date.now()+28800000},c.sessionSecret);
  return reply({ok:true,name:p.name||p.email},200,{'Set-Cookie':'modolog_portal='+token+'; '+cookieOptions});
 }catch(e){console.error('Portal authentication failed:',e?.message||'unknown');return reply({error:'Falha na comunicação com o serviço de autenticação.'},502);}
}
export async function onRequestDelete(){return reply({ok:true},200,{'Set-Cookie':'modolog_portal=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'});}
