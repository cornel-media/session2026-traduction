// TransLive Token Server — multi-tenant
// Endpoints:
//   GET /listen?room=X&name=Y                 -> subscriber-only token (anonymous)
//   GET /broadcast?room=X&name=Y&password=P   -> publisher token (room-specific password)
//
// How room → password is resolved:
//   SDAQC                       -> env.INTERPRETER_PASSWORD   (legacy, Fédération)
//   anything else, e.g. "foo-x" -> env.PASSWORD_FOO_X         (uppercase, non-alnum → _)
// To add a new church: just add a new Cloudflare secret named PASSWORD_<ROOMUPPER>.
// No code change needed.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function b64url(input) {
  let bytes;
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else {
    bytes = new Uint8Array(input);
  }
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const data = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${b64url(sig)}`;
}

async function makeToken({ apiKey, apiSecret, room, identity, name, canPublish }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: apiKey,
    sub: identity,
    iat: now,
    nbf: now,
    exp: now + 6 * 60 * 60, // 6 hours
    name: name || identity,
    video: {
      room: room,
      roomJoin: true,
      canPublish: !!canPublish,
      canSubscribe: true,
      canPublishData: !!canPublish,
    },
  };
  return await signJWT(payload, apiSecret);
}

function envKeyForRoom(room) {
  if (room === 'SDAQC') return 'INTERPRETER_PASSWORD';
  return 'PASSWORD_' + room.toUpperCase().replace(/[^A-Z0-9]/g, '_');
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const room = url.searchParams.get('room') || 'SDAQC';
    const name = url.searchParams.get('name') || 'anonymous';
    const identity = `${name}-${crypto.randomUUID().slice(0, 8)}`;

    if (!env.LIVEKIT_URL || !env.LIVEKIT_API_KEY || !env.LIVEKIT_API_SECRET) {
      return json({ error: 'Server not configured' }, 500);
    }

    if (path === '/listen') {
      const token = await makeToken({
        apiKey: env.LIVEKIT_API_KEY,
        apiSecret: env.LIVEKIT_API_SECRET,
        room, identity, name,
        canPublish: false,
      });
      return json({ serverUrl: env.LIVEKIT_URL, participantToken: token, roomName: room });
    }

    if (path === '/broadcast') {
      const password = url.searchParams.get('password') || '';
      const envKey = envKeyForRoom(room);
      const expected = env[envKey];
      if (!expected || password !== expected) {
        return json({ error: 'Invalid password or unknown room' }, 401);
      }
      const token = await makeToken({
        apiKey: env.LIVEKIT_API_KEY,
        apiSecret: env.LIVEKIT_API_SECRET,
        room, identity, name,
        canPublish: true,
      });
      return json({ serverUrl: env.LIVEKIT_URL, participantToken: token, roomName: room });
    }

    return json({ service: 'TransLive API', endpoints: ['/listen', '/broadcast'] });
  },
};
