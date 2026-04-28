require('dotenv').config();
const express          = require('express');
const http             = require('http');
const { Server }      = require('socket.io');
const cors            = require('cors');
const helmet          = require('helmet');
const crypto          = require('crypto');
const { nanoid }      = require('nanoid');
const tmi             = require('tmi.js');
const axios           = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

app.use(cors());
app.use(helmet());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

function signToken(token, username) {
  return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(token + normalizeUsername(username)).digest('hex').slice(0, 16);
}

function verifyToken(token, username, sig) {
  if (!token || !username || !sig) return false;
  const expected = signToken(token, username);
  try { return crypto.timingSafeEqual(Buffer.from(String(sig).padEnd(16, '0')), Buffer.from(expected)); }
  catch { return false; }
}

let appAccessToken = null;

// ── Diccionario de fantasmas: comando → nombre oficial en el tablero ──
const GHOST_ALIASES = {
  'espirito':    'Espíritu',
  'espiritu':    'Espíritu',
  'poltergeist': 'Poltergeist',
  'ente':        'Ente',
  'espectro':    'Espectro',
  'demonio':     'Demonio',
  'yurei':       'Yurei',
  'oni':         'Oni',
  'yokai':       'Yokai',
  'hantu':       'Hantu',
  'goryo':       'Goryo',
  'myling':      'Myling',
  'onryo':       'Onryo',
  'gemelos':     'Gemelos',
  'raiju':       'Raiju',
  'obake':       'Obake',
  'mimico':      'Mímico',
  'mímico':      'Mímico',
  'moroi':       'Moroi',
  'deogen':      'Deogen',
  'thaye':       'Thaye',
  'revenant':    'Revenant',
  'sombra':      'Sombra',
  'banshee':     'Banshee',
  'jinn':        'Jinn',
  'pesadilla':   'Pesadilla'
};

async function getAppToken() {
  const res = await axios.post('https://id.twitch.tv/oauth2/token', null, {
    params: {
      client_id: process.env.TWITCH_CLIENT_ID,
      client_secret: process.env.TWITCH_CLIENT_SECRET,
      grant_type: 'client_credentials'
    }
  });
  appAccessToken = res.data.access_token;
  return appAccessToken;
}

async function twitchGet(url, params) {
  if (!appAccessToken) await getAppToken();
  const headers = {
    'Client-ID': process.env.TWITCH_CLIENT_ID,
    'Authorization': 'Bearer ' + appAccessToken
  };
  try {
    return await axios.get(url, { params, headers });
  } catch (err) {
    if (err.response?.status === 401) {
      await getAppToken();
      headers.Authorization = 'Bearer ' + appAccessToken;
      return await axios.get(url, { params, headers });
    }
    throw err;
  }
}

async function getUserId(username) {
  const res = await twitchGet('https://api.twitch.tv/helix/users', { login: username });
  return res.data.data?.[0]?.id || null;
}

async function getChannelId() {
  const res = await twitchGet('https://api.twitch.tv/helix/users', { login: process.env.TWITCH_CHANNEL });
  return res.data.data?.[0]?.id || null;
}

async function validateUserSubscription(userId, channelId) {
  try {
    const res = await twitchGet('https://api.twitch.tv/helix/subscriptions/user', {
      broadcaster_id: channelId,
      user_id: userId
    });
    return (res.data.data?.length || 0) > 0;
  } catch { return false; }
}

async function validateFollow(userId, channelId) {
  try {
    const res = await twitchGet('https://api.twitch.tv/helix/channels/followers', {
      broadcaster_id: channelId,
      user_id: userId
    });
    if (!res.data.data?.length) return false;
    const followedAt = new Date(res.data.data[0].followed_at);
    const months = (Date.now() - followedAt.getTime()) / (1000 * 60 * 60 * 24 * 30.44);
    return months >= 3;
  } catch { return false; }
}

async function checkEligibility(username) {
  try {
    const [userId, channelId] = await Promise.all([getUserId(username), getChannelId()]);
    if (!userId || !channelId) return false;
    return (await validateUserSubscription(userId, channelId)) || (await validateFollow(userId, channelId));
  } catch (err) {
    console.error('[Bot] Error validando elegibilidad:', err.message);
    return false;
  }
}

async function isModOrBroadcaster(username) {
  const lower   = username.toLowerCase();
  const channel = process.env.TWITCH_CHANNEL.toLowerCase();
  if (lower === channel) return true;
  try {
    const res = await twitchGet('https://api.twitch.tv/helix/moderation/moderators', {
      broadcaster_id: await getChannelId(),
      user_id: await getUserId(lower)
    });
    return (res.data.data || []).some(u => u.user_login.toLowerCase() === lower);
  } catch { return false; }
}

async function saveBroadcasterToken(username, accessToken, refreshToken) {
  const { data: existing } = await supabase.from('broadcaster_token').select('id').eq('username', username).maybeSingle();
  if (existing) {
    await supabase.from('broadcaster_token').update({ access_token: accessToken, refresh_token: refreshToken, updated_at: new Date().toISOString() }).eq('username', username);
  } else {
    await supabase.from('broadcaster_token').insert({ username, access_token: accessToken, refresh_token: refreshToken });
  }
}

async function loadBroadcasterToken() {
  const { data, error } = await supabase.from('broadcaster_token').select('*').limit(1);
  if (error) { console.error('[Auth] Error cargando broadcaster token:', error.message); return; }
  if (!data || data.length === 0) {
    console.log('[Auth] No hay token del broadcaster. El streamer debe autorizar en: https://phasmobingo.ddnsfree.com/auth/twitch?role=broadcaster');
    return;
  }
  const row = data[0];
  const valid = await validateBroadcasterToken(row.access_token);
  if (valid) {
    broadcasterToken = row.access_token;
    broadcasterRefreshToken = row.refresh_token;
    console.log('[Auth] Token del broadcaster cargado correctamente');
  } else {
    await refreshBroadcasterToken(row);
  }
}

async function validateBroadcasterToken(token) {
  try {
    const res = await axios.get('https://id.twitch.tv/oauth2/validate', { headers: { 'Authorization': 'OAuth ' + token } });
    return res.status === 200;
  } catch { return false; }
}

async function refreshBroadcasterToken(row) {
  try {
    console.log('[Auth] Refrescando token del broadcaster...');
    const res = await axios.post('https://id.twitch.tv/oauth2/token', null, {
      params: { client_id: process.env.TWITCH_CLIENT_ID, client_secret: process.env.TWITCH_CLIENT_SECRET, grant_type: 'refresh_token', refresh_token: row.refresh_token }
    });
    broadcasterToken = res.data.access_token;
    broadcasterRefreshToken = res.data.refresh_token;
    await supabase.from('broadcaster_token').update({ access_token: broadcasterToken, refresh_token: broadcasterRefreshToken, updated_at: new Date().toISOString() }).eq('username', row.username);
    console.log('[Auth] Token del broadcaster refrescado');
  } catch (err) { console.error('[Auth] Error refrescando token:', err.message); }
}

async function getLeaderboard() {
  const { data } = await supabase.from('leaderboard').select('username, points').order('points', { ascending: false }).limit(10);
  return data || [];
}

async function addPoints(username, points) {
  const { data: existing } = await supabase.from('leaderboard').select('points').eq('username', username).maybeSingle();
  if (existing) {
    await supabase.from('leaderboard').update({ points: existing.points + points, updated_at: new Date().toISOString() }).eq('username', username);
  } else {
    await supabase.from('leaderboard').insert({ username, points });
  }
}

let broadcasterToken = null;
let broadcasterRefreshToken = null;
let currentStream = null;

const botClient = new tmi.Client({
  options: { debug: false },
  identity: { username: process.env.TWITCH_BOT_USERNAME, password: 'oauth:' + process.env.TWITCH_BOT_OAUTH },
  channels: [process.env.TWITCH_CHANNEL]
});

function say(msg) {
  botClient.say('#' + process.env.TWITCH_CHANNEL, msg);
}

botClient.on('message', async (channel, tags, message, self) => {
  if (self) return;
  const displayName = tags['display-name'] || tags.username;
  const username    = normalizeUsername(displayName);
  const msg         = message.trim().toLowerCase();

  if (msg === '!phasmobingo') {
    if (!currentStream) { say('Lo siento @' + displayName + ', no hay ningun stream activo en este momento.'); return; }
    if (currentStream.bingos_won >= 2) { say('Lo siento @' + displayName + ', el bingo de hoy ya ha finalizado.'); return; }
    const { data: existing } = await supabase.from('sessions').select('token').eq('username', username).eq('stream_id', currentStream.stream_id).eq('status', 'active').maybeSingle();
    if (existing) {
      const sig = signToken(existing.token, username);
      say('@' + displayName + ' ya estas participando en este stream: https://computinworks.github.io/phasmobingo/' + existing.token + '?u=' + username + '&sig=' + sig);
      return;
    }
    const eligible = await checkEligibility(username);
    if (!eligible) { say('Lo siento @' + displayName + ', necesitas ser seguidor con al menos 3 meses de antiguedad o suscriptor para participar.'); return; }
    const token = nanoid();
    const seed  = nanoid(8);
    const sig   = signToken(token, username);
    const { error } = await supabase.from('sessions').insert({ token, username, seed, stream_id: currentStream.stream_id, status: 'active' });
    if (error) { console.error('[Bot] Error creando sesion:', error.message); say('Lo siento @' + displayName + ', hubo un error. Intenta de nuevo.'); return; }
    say('@' + displayName + ' tu tablon esta listo: https://computinworks.github.io/phasmobingo/' + token + '?u=' + username + '&sig=' + sig);
    return;
  }

  const ghost = GHOST_ALIASES[msg];
  if (ghost) {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) { say('@' + displayName + ', solo moderadores o el broadcaster pueden cantar fantasmas.'); return; }
    if (!currentStream) { say('No hay stream activo.'); return; }
    if (currentStream.called_ghosts.map(g => g.toLowerCase()).includes(ghost.toLowerCase())) { say(ghost + ' ya fue cantado anteriormente.'); return; }
    currentStream.called_ghosts.push(ghost);
    await supabase.from('streams').update({ called_ghosts: currentStream.called_ghosts }).eq('stream_id', currentStream.stream_id);
    io.emit('ghost_caught', ghost);
    say(ghost + ' cantado correctamente.');
    return;
  }

  if (msg === '!leaderboard') {
    const board = await getLeaderboard();
    const medals = ['🥇', '🥈', '🥉'];
    say('Tabla de Posiciones: ' + board.map((r, i) => (medals[i] || (i + 1) + 'o') + ' ' + r.username + ' - ' + r.points + ' pts').join(' | '));
    return;
  }

  if (msg === '!pbend') {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) { say('@' + displayName + ', solo moderadores pueden finalizar el bingo.'); return; }
    if (currentStream) await endStream();
    return;
  }

  if (msg === '!pbreset') {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) { say('@' + displayName + ', solo moderadores pueden reiniciar el bingo.'); return; }
    if (!currentStream) { say('No hay bingo activo.'); return; }
    currentStream.called_ghosts = [];
    currentStream.bingos_won = 0;
    await supabase.from('streams').update({ called_ghosts: [], bingos_won: 0 }).eq('stream_id', currentStream.stream_id);
    say('Bingo reiniciado.');
    io.emit('reset_board');
    return;
  }

  if (msg === '!pbsync') {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) { say('@' + displayName + ', solo moderadores pueden sincronizar.'); return; }
    await syncCurrentStream();
    say('Sincronizacion completada.');
    return;
  }
});

botClient.on('connected', (addr, port) => console.log('[Bot] Conectado a Twitch en ' + addr + ':' + port));
botClient.on('disconnected', reason => console.warn('[Bot] Desconectado:', reason));

app.get('/api/sign', (req, res) => {
  const { token, u: username } = req.query;
  const normalizedUsername = normalizeUsername(username);
  if (!token || !normalizedUsername) return res.status(400).json({ error: 'Faltan parametros' });
  res.json({ sig: signToken(token, normalizedUsername) });
});

app.get('/auth/twitch', (req, res) => {
  const role     = req.query.role || 'viewer';
  const returnTo = req.query.returnTo || '';
  const scopes   = role === 'broadcaster'
    ? 'moderator:read:followers moderation:read channel:read:subscriptions channel:bot'
    : 'user:read:email';
  const state  = crypto.randomBytes(16).toString('hex') + '|' + returnTo;
  const params = new URLSearchParams({ client_id: process.env.TWITCH_CLIENT_ID, redirect_uri: 'https://' + process.env.FRONTEND_URL + '/auth/callback', response_type: 'code', scope: scopes, state, force_verify: 'true' });
  res.redirect('https://id.twitch.tv/oauth2/authorize?' + params);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code) return res.redirect('https://computinworks.github.io/phasmobingo/?auth=error');
  const returnTo = state ? (state.split('|')[1] || '') : '';
  try {
    const tokenRes = await axios.post('https://id.twitch.tv/oauth2/token', null, {
      params: {
        client_id: process.env.TWITCH_CLIENT_ID,
        client_secret: process.env.TWITCH_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: 'https://' + process.env.FRONTEND_URL + '/auth/callback'
      }
    });
    const accessToken = tokenRes.data.access_token;
    const refreshToken = tokenRes.data.refresh_token;
    const userRes = await axios.get('https://api.twitch.tv/helix/users', {
      headers: { 'Client-ID': process.env.TWITCH_CLIENT_ID, 'Authorization': 'Bearer ' + accessToken }
    });
    const username = userRes.data.data[0].login.toLowerCase();
    if (username === process.env.TWITCH_CHANNEL.toLowerCase()) {
      await saveBroadcasterToken(username, accessToken, refreshToken);
      return res.redirect('https://computinworks.github.io/phasmobingo/' + returnTo + '?auth=ok&role=broadcaster');
    }
    return res.redirect('https://computinworks.github.io/phasmobingo/' + returnTo + '?auth=ok&u=' + username);
  } catch (err) {
    console.error('[Auth] Error en callback:', err.message);
    return res.redirect('https://computinworks.github.io/phasmobingo/?auth=error');
  }
});

app.get('/api/session/:token', async (req, res) => {
  const { token } = req.params;
  const { u: username, sig } = req.query;
  const normalizedUsername = normalizeUsername(username);
  if (!token) return res.json({ status: 'invalid' });
  const { data: session, error } = await supabase.from('sessions').select('*').eq('token', token).maybeSingle();
  if (error || !session) return res.json({ status: 'invalid' });
  if (!normalizedUsername || !sig || !verifyToken(token, normalizedUsername, sig)) return res.json({ status: 'invalid' });
  if (session.status === 'expired') return res.json({ status: 'expired' });
  const { data: stream } = await supabase.from('streams').select('*').eq('stream_id', session.stream_id).maybeSingle();
  const isOwner   = normalizedUsername === normalizeUsername(session.username);
  const gameEnded = (stream?.bingos_won || 0) >= 2;
  return res.json({ status: session.status, username: session.username, seed: session.seed, marked: session.marked || [], called_ghosts: stream?.called_ghosts || [], leaderboard: await getLeaderboard(), isOwner, gameEnded });
});

app.post('/api/session/:token/progress', async (req, res) => {
  const { token } = req.params;
  const { u: username, sig } = req.query;
  const normalizedUsername = normalizeUsername(username);
  const { marked } = req.body;
  if (!verifyToken(token, normalizedUsername, sig)) return res.status(403).json({ error: 'Firma invalida' });
  if (!Array.isArray(marked)) return res.status(400).json({ error: 'Formato invalido' });
  const { error } = await supabase.from('sessions').update({ marked }).eq('token', token).eq('username', normalizedUsername);
  if (error) return res.status(500).json({ error: 'Error guardando progreso' });
  return res.json({ ok: true });
});

app.post('/api/session/:token/bingo', async (req, res) => {
  const { token } = req.params;
  const { u: username, sig } = req.query;
  const normalizedUsername = normalizeUsername(username);
  const { line, cells } = req.body;
  if (!verifyToken(token, normalizedUsername, sig)) return res.status(403).json({ error: 'Firma invalida' });
  if (!Array.isArray(line) || !Array.isArray(cells)) return res.status(400).json({ error: 'Formato invalido' });
  if (!currentStream || currentStream.bingos_won >= 2) return res.json({ valid: false, reason: 'Bingo no activo o ya finalizado' });
  const { data: session } = await supabase.from('sessions').select('*').eq('token', token).maybeSingle();
  if (!session) return res.json({ valid: false, reason: 'Sesion no encontrada' });
  const allValid = line.every(idx => {
    const ghost = cells[idx];
    if (!ghost) return false;
    if (ghost === 'LIBRE') return true;
    return currentStream.called_ghosts.map(g => g.toLowerCase()).includes(ghost.toLowerCase());
  });
  if (!allValid) return res.json({ valid: false, reason: 'Celdas no validas' });
  currentStream.bingos_won += 1;
  const bingoNumber = currentStream.bingos_won;
  const points = bingoNumber === 1 ? 10 : 5;
  await supabase.from('streams').update({ bingos_won: bingoNumber }).eq('stream_id', currentStream.stream_id);
  await addPoints(session.username, points);
  const leaderboard = await getLeaderboard();
  io.emit('leaderboard_update', leaderboard);
  io.emit('bingo_won', { username: session.username, bingoNumber, points });
  if (bingoNumber === 1) {
    say('Bingo! @' + session.username + ' ha completado el primer bingo. Solo queda 1 bingo restante.');
  } else {
    say('Bingo! @' + session.username + ' ha completado el segundo bingo. Bingo finalizado, gracias a todos por participar!');
    io.emit('game_over');
    await supabase.from('sessions').update({ status: 'readonly' }).eq('stream_id', currentStream.stream_id);
  }
  return res.json({ valid: true, points, bingoNumber });
});

app.get('/api/leaderboard', async (req, res) => {
  return res.json({ leaderboard: await getLeaderboard() });
});

async function syncCurrentStream() {
  if (!currentStream) return;
  const { data } = await supabase.from('streams').select('*').eq('stream_id', currentStream.stream_id).maybeSingle();
  if (!data) return;
  currentStream.called_ghosts = data.called_ghosts || [];
  currentStream.bingos_won = data.bingos_won || 0;
}

async function startNewStream(stream_id) {
  currentStream = { stream_id, called_ghosts: [], bingos_won: 0 };
  await supabase.from('streams').upsert({ stream_id, called_ghosts: [], bingos_won: 0 });
  io.emit('new_stream', { stream_id });
}

async function endStream() {
  if (!currentStream) return;
  await supabase.from('sessions').update({ status: 'expired' }).eq('stream_id', currentStream.stream_id);
  io.emit('game_over');
  currentStream = null;
  say('PhasmoBingo finalizado. Hasta el proximo stream!');
}

setInterval(async () => {
  try {
    if (!currentStream) return;
    const { data } = await supabase.from('streams').select('*').eq('stream_id', currentStream.stream_id).maybeSingle();
    if (!data) return;
    currentStream.called_ghosts = data.called_ghosts || [];
    currentStream.bingos_won = data.bingos_won || 0;
  } catch {}
}, 15000);

server.listen(process.env.PORT || 3000, async () => {
  console.log('Servidor listo en puerto ' + (process.env.PORT || 3000));
  await loadBroadcasterToken();
  await botClient.connect();
});