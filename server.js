require('dotenv').config();
const express          = require('express');
const http             = require('http');
const { Server }       = require('socket.io');
const cors             = require('cors');
const helmet           = require('helmet');
const crypto           = require('crypto');
const { nanoid }       = require('nanoid');
const tmi              = require('tmi.js');
const axios            = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

app.use(cors());
app.use(helmet());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function signToken(token, username) {
  return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(token + username).digest('hex').slice(0, 16);
}

function verifyToken(token, username, sig) {
  if (!token || !username || !sig) return false;
  const expected = signToken(token, username);
  try { return crypto.timingSafeEqual(Buffer.from(sig.padEnd(16, '0')), Buffer.from(expected)); }
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
    params: { client_id: process.env.TWITCH_CLIENT_ID, client_secret: process.env.TWITCH_CLIENT_SECRET, grant_type: 'client_credentials' }
  });
  appAccessToken = res.data.access_token;
  console.log('[Twitch] App token obtenido');
}

async function twitchGet(url, params) {
  return axios.get(url, { params, headers: { 'Client-ID': process.env.TWITCH_CLIENT_ID, 'Authorization': 'Bearer ' + appAccessToken } }).catch(() => null);
}

async function getUserId(username) {
  const res = await twitchGet('https://api.twitch.tv/helix/users', { login: username });
  return res?.data?.data?.[0]?.id || null;
}

let cachedChannelId = null;
async function getChannelId() {
  if (cachedChannelId) return cachedChannelId;
  cachedChannelId = await getUserId(process.env.TWITCH_CHANNEL);
  return cachedChannelId;
}

let broadcasterToken = null;
let broadcasterRefreshToken = null;

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
    console.log('[Auth] Token del broadcaster refrescado correctamente');
  } catch (err) {
    console.error('[Auth] Error refrescando token:', err.message);
    console.log('[Auth] El streamer necesita re-autorizar en: https://phasmobingo.ddnsfree.com/auth/twitch?role=broadcaster');
  }
}

async function saveBroadcasterToken(username, accessToken, refreshToken) {
  const { data: existing } = await supabase.from('broadcaster_token').select('id').eq('username', username).maybeSingle();
  if (existing) {
    await supabase.from('broadcaster_token').update({ access_token: accessToken, refresh_token: refreshToken, updated_at: new Date().toISOString() }).eq('username', username);
  } else {
    await supabase.from('broadcaster_token').insert({ username, access_token: accessToken, refresh_token: refreshToken });
  }
  broadcasterToken = accessToken;
  broadcasterRefreshToken = refreshToken;
  console.log('[Auth] Token del broadcaster guardado en Supabase');
}

async function checkEligibility(username) {
  try {
    if (!broadcasterToken) { console.warn('[Eligibility] No hay token del broadcaster'); return false; }
    const [userId, channelId] = await Promise.all([getUserId(username), getChannelId()]);
    if (!userId || !channelId) return false;
    const subRes = await axios.get('https://api.twitch.tv/helix/subscriptions/user', {
      params: { broadcaster_id: channelId, user_id: userId },
      headers: { 'Client-ID': process.env.TWITCH_CLIENT_ID, 'Authorization': 'Bearer ' + broadcasterToken }
    }).catch(() => null);
    if (subRes?.data?.data?.length > 0) return true;
    const followRes = await axios.get('https://api.twitch.tv/helix/channels/followers', {
      params: { broadcaster_id: channelId, user_id: userId },
      headers: { 'Client-ID': process.env.TWITCH_CLIENT_ID, 'Authorization': 'Bearer ' + broadcasterToken }
    }).catch(() => null);
    if (!followRes?.data?.data?.length) return false;
    const followedAt = new Date(followRes.data.data[0].followed_at);
    const monthsDiff = (Date.now() - followedAt.getTime()) / (1000 * 60 * 60 * 24 * 30);
    return monthsDiff >= 3;
  } catch (err) { console.error('[Eligibility] Error:', err.message); return false; }
}

async function isModOrBroadcaster(username) {
  const lower   = username.toLowerCase();
  const channel = process.env.TWITCH_CHANNEL.toLowerCase();

  // El streamer siempre tiene permiso
  if (lower === channel) return true;

  // Lista de mods autorizados manualmente
  const MODS_AUTORIZADOS = [
    'lecarletti'
    // agrega mas mods aqui si es necesario
  ];
  if (MODS_AUTORIZADOS.includes(lower)) return true;

  if (!broadcasterToken) { console.warn('[Mod] No hay token del broadcaster.'); return false; }
  try {
    const [userId, channelId] = await Promise.all([getUserId(lower), getChannelId()]);
    if (!userId || !channelId) return false;
    const res = await axios.get('https://api.twitch.tv/helix/moderation/moderators', {
      params: { broadcaster_id: channelId, user_id: userId },
      headers: { 'Client-ID': process.env.TWITCH_CLIENT_ID, 'Authorization': 'Bearer ' + broadcasterToken }
    }).catch(() => null);
    return (res?.data?.data?.length || 0) > 0;
  } catch (err) { console.error('[Mod] Error:', err.message); return false; }
}

let currentStream = null;

async function loadCurrentStream() {
  const { data, error } = await supabase.from('streams').select('*').eq('status', 'active').limit(1);
  if (error) { console.error('[Stream] Error:', error.message); return; }
  const row = data?.[0];
  if (!row) { console.log('[Stream] No hay stream activo'); return; }
  currentStream = { stream_id: row.stream_id, bingos_won: row.bingos_won, called_ghosts: row.called_ghosts || [] };
  console.log('[Stream] Stream activo encontrado:', row.stream_id);
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

const botClient = new tmi.Client({
  options: { debug: false },
  identity: { username: process.env.TWITCH_BOT_USERNAME, password: 'oauth:' + process.env.TWITCH_BOT_OAUTH },
  channels: [process.env.TWITCH_CHANNEL]
});

function say(msg) {
  botClient.say(process.env.TWITCH_CHANNEL, msg).catch(err => console.error('[Bot] Error:', err.message));
}

botClient.on('message', async (channel, tags, message, self) => {
  if (self) return;
  const displayName = tags['display-name'] || tags.username;
  const username    = displayName.toLowerCase();
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

  const specialCmds = ['!pbtabla', '!pbborrar', '!pbstart', '!pbend'];
  if (msg.startsWith('!pb') && msg.length > 3 && !specialCmds.includes(msg)) {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) return;
    if (!currentStream) { say('No hay ningun bingo activo.'); return; }
    if (currentStream.bingos_won >= 2) { say('El bingo ya finalizo, no se pueden cantar mas fantasmas.'); return; }

    const ghostKey = msg.slice(3).trim();
    const ghost    = GHOST_ALIASES[ghostKey];

    if (!ghost) {
      say('Fantasma no reconocido: ' + ghostKey + '. Usa uno de los 24 fantasmas del tablero.');
      return;
    }

    if (currentStream.called_ghosts.map(g => g.toLowerCase()).includes(ghost.toLowerCase())) { say(ghost + ' ya fue cantado anteriormente.'); return; }
    currentStream.called_ghosts.push(ghost);
    const { error } = await supabase.from('streams').update({ called_ghosts: currentStream.called_ghosts }).eq('stream_id', currentStream.stream_id);
    if (error) { console.error('[Bot] Error guardando fantasma:', error.message); return; }
    io.emit('ghost_called', { name: ghost, order: currentStream.called_ghosts.length });
    say(ghost + ' cantado! (#' + currentStream.called_ghosts.length + ')');
    return;
  }

  if (msg === '!pbtabla') {
    const board = await getLeaderboard();
    if (!board.length) { say('La tabla de posiciones esta vacia.'); return; }
    const medals = ['1o', '2o', '3o'];
    say('Tabla de Posiciones: ' + board.map((r, i) => (medals[i] || (i + 1) + 'o') + ' ' + r.username + ' - ' + r.points + ' pts').join(' | '));
    return;
  }

  if (msg === '!pbborrar') {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) return;
    const { error } = await supabase.from('leaderboard').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    if (error) { console.error('[Bot] Error borrando leaderboard:', error.message); return; }
    io.emit('leaderboard_reset');
    say('La tabla de posiciones ha sido reiniciada.');
    return;
  }

  if (msg === '!pbstart') {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) return;
    if (currentStream) { say('Ya hay un bingo activo.'); return; }
    const stream_id = 'stream_' + Date.now();
    const { error } = await supabase.from('streams').insert({ stream_id, status: 'active', called_ghosts: [], bingos_won: 0 });
    if (error) { console.error('[Bot] Error iniciando stream:', error.message); return; }
    currentStream = { stream_id, bingos_won: 0, called_ghosts: [] };
    say('PhasmoBingo iniciado! Escribe !phasmobingo para obtener tu tablon.');
    return;
  }

  if (msg === '!pbend') {
    const isMod = await isModOrBroadcaster(username);
    if (!isMod) return;
    if (!currentStream) { say('No hay ningun bingo activo.'); return; }
    await supabase.from('streams').update({ status: 'ended', ended_at: new Date().toISOString() }).eq('stream_id', currentStream.stream_id);
    await supabase.from('sessions').update({ status: 'expired' }).eq('stream_id', currentStream.stream_id);
    io.emit('stream_ended');
    currentStream = null;
    say('PhasmoBingo finalizado. Hasta el proximo stream!');
    return;
  }
});

botClient.on('connected', (addr, port) => console.log('[Bot] Conectado a Twitch en ' + addr + ':' + port));
botClient.on('disconnected', reason => console.warn('[Bot] Desconectado:', reason));

app.get('/api/sign', (req, res) => {
  const { token, u: username } = req.query;
  if (!token || !username) return res.status(400).json({ error: 'Faltan parametros' });
  res.json({ sig: signToken(token, username) });
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
      params: { client_id: process.env.TWITCH_CLIENT_ID, client_secret: process.env.TWITCH_CLIENT_SECRET, code, grant_type: 'authorization_code', redirect_uri: 'https://' + process.env.FRONTEND_URL + '/auth/callback' }
    });
    const accessToken  = tokenRes.data.access_token;
    const refreshToken = tokenRes.data.refresh_token;
    const userRes = await axios.get('https://api.twitch.tv/helix/users', { headers: { 'Authorization': 'Bearer ' + accessToken, 'Client-ID': process.env.TWITCH_CLIENT_ID } });
    const username = userRes.data.data[0].login.toLowerCase();
    if (username === process.env.TWITCH_CHANNEL.toLowerCase()) {
      await saveBroadcasterToken(username, accessToken, refreshToken);
      return res.redirect('https://computinworks.github.io/phasmobingo/?auth=broadcaster_ok');
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
  if (!token) return res.json({ status: 'invalid' });
  const { data: session, error } = await supabase.from('sessions').select('*').eq('token', token).maybeSingle();
  if (error || !session) return res.json({ status: 'invalid' });
  if (!username || !sig || !verifyToken(token, username, sig)) return res.json({ status: 'invalid' });
  if (session.status === 'expired') return res.json({ status: 'expired' });
  const { data: stream } = await supabase.from('streams').select('*').eq('stream_id', session.stream_id).maybeSingle();
  const isOwner   = username.toLowerCase() === session.username.toLowerCase();
  const gameEnded = (stream?.bingos_won || 0) >= 2;
  return res.json({ status: session.status, username: session.username, seed: session.seed, marked: session.marked || [], called_ghosts: stream?.called_ghosts || [], leaderboard: await getLeaderboard(), isOwner, gameEnded });
});

app.post('/api/session/:token/progress', async (req, res) => {
  const { token } = req.params;
  const { u: username, sig } = req.query;
  const { marked } = req.body;
  if (!verifyToken(token, username, sig)) return res.status(403).json({ error: 'Firma invalida' });
  if (!Array.isArray(marked)) return res.status(400).json({ error: 'Formato invalido' });
  const { error } = await supabase.from('sessions').update({ marked }).eq('token', token).eq('username', username.toLowerCase());
  if (error) return res.status(500).json({ error: 'Error guardando progreso' });
  return res.json({ ok: true });
});

app.post('/api/session/:token/bingo', async (req, res) => {
  const { token } = req.params;
  const { u: username, sig } = req.query;
  const { line, cells } = req.body;
  if (!verifyToken(token, username, sig)) return res.status(403).json({ error: 'Firma invalida' });
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

app.get('/api/leaderboard', async (req, res) => res.json(await getLeaderboard()));

io.on('connection', socket => {
  console.log('[WS] Cliente conectado:', socket.id);
  socket.on('disconnect', () => console.log('[WS] Cliente desconectado:', socket.id));
});

async function start() {
  try {
    await getAppToken();
    await loadBroadcasterToken();
    await loadCurrentStream();
    await botClient.connect();
    server.listen(process.env.PORT || 3000, () => console.log('[Server] Corriendo en puerto ' + (process.env.PORT || 3000)));
  } catch (err) {
    console.error('[Start] Error iniciando servidor:', err.message);
    process.exit(1);
  }
}

start();
