
const encoder = new TextEncoder();

const b64 = bytes =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const from64 = str =>
  Uint8Array.from(
    atob(str.replace(/-/g, '+').replace(/_/g, '/') +
      '='.repeat((4 - str.length % 4) % 4)),
    x => x.charCodeAt(0)
  );

const secretKey = s =>
  crypto.subtle.importKey(
    'raw',
    encoder.encode(s),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

export const headers = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff'
};

export const reply = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      ...headers,
      'Content-Type': 'application/json; charset=utf-8',
      ...extra
    }
  });

export function settings(env) {
  return {
    url: String(env.SUPABASE_URL || '').replace(/\/$/, ''),
    publicKey: env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY || '',
    adminKey: env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY || '',
    sessionSecret: env.PORTAL_SESSION_SECRET || ''
  };
}

export function configured(c) {
  return /^https:\/\/[^/]+/.test(c.url) &&
    !!c.publicKey &&
    !!c.adminKey &&
    c.sessionSecret.length >= 32;
}

export function adminHeaders(c) {
  return {
    apikey: c.adminKey,
    ...(c.adminKey.startsWith('sb_secret_')
      ? {}
      : { Authorization: 'Bearer ' + c.adminKey })
  };
}

export async function sign(payload, secret) {
  const data = b64(encoder.encode(JSON.stringify(payload)));
  const sig = b64(
    new Uint8Array(
      await crypto.subtle.sign(
        'HMAC',
        await secretKey(secret),
        encoder.encode(data)
      )
    )
  );
  return data + '.' + sig;
}

export async function verify(token, secret) {
  try {
    if (!token || token.length > 4096) return null;
    const [data, sig, extra] = token.split('.');
    if (!data || !sig || extra) return null;

    const ok = await crypto.subtle.verify(
      'HMAC',
      await secretKey(secret),
      from64(sig),
      encoder.encode(data)
    );

    if (!ok) return null;

    const p = JSON.parse(
      new TextDecoder().decode(from64(data))
    );

    return typeof p.sub === 'string' && p.exp > Date.now()
      ? p
      : null;
  } catch {
    return null;
  }
}

export function getCookie(req) {
  const raw = req.headers.get('Cookie') || '';
  return raw
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith('modolog_portal='))
    ?.slice('modolog_portal='.length) || '';
}

export const cookieOptions =
  'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800';

export async function getProfile(c, id) {
  const u = c.url +
    '/rest/v1/modolog_profiles?id=eq.' +
    encodeURIComponent(id) +
    '&select=id,name,email,role,active&limit=1';

  let r;

  try {
    r = await fetch(u, {
      headers: adminHeaders(c),
      redirect: 'follow'
    });
  } catch (e) {
    console.error('Profile fetch failed:', e?.message);
    throw Error('profile_network');
  }

  if (!r.ok) {
    console.error('Profile query HTTP:', r.status);
    throw Error('profile_http_' + r.status);
  }

  const rows = await r.json();
  const p = rows?.[0];

  return p?.active &&
    ['master', 'admin', 'operador'].includes(p.role)
      ? p
      : null;
}

export async function session(req, env) {
  const c = settings(env);
  if (!configured(c)) return null;

  const payload = await verify(
    getCookie(req),
    c.sessionSecret
  );

  if (!payload) return null;

  return getProfile(c, payload.sub);
}
