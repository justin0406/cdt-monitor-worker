/**
 * CDT-Monitor Worker 主入口
 * 路由对应原版 index.php 的 ?action=xxx 接口
 *
 * 鉴权模型：
 *  - 面板：HMAC 会话 Cookie（密钥来自 env.SESSION_SECRET，未配置时自动生成并存入 D1）
 *  - 外部自动化（Scriptable / 快捷指令）：GET /api/v1/status + Bearer <api_key>
 */
import { Store } from './store';
import { Monitor } from './monitor';
import { Notifier } from './notify';

interface Env {
  DB: any;
  ASSETS?: any;
  SESSION_SECRET?: string;
}

const COOKIE_NAME = 'cdt_admin';
const SESSION_TTL = 7 * 24 * 3600; // 7 天
/** 前端提交的掩码值前缀：命中即视为"未修改"，保留库中原值 */
const MASK_PREFIX = '********';

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
};

function json(data: any, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function clientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || '0.0.0.0';
}

function randomHex(bytes = 24): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array | null {
  if (!hex || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

async function hmacSign(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
}

/** 常数时间字符串比较（先哈希消除长度差异） */
async function safeEqual(a: string, b: string): Promise<boolean> {
  if (!a || !b || a.length !== b.length) return false;
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export function maskSecret(value: string | null | undefined): string {
  const s = String(value || '');
  if (!s) return '';
  return MASK_PREFIX + s.slice(-4);
}

export function isMasked(value: any): boolean {
  return typeof value === 'string' && value.startsWith(MASK_PREFIX);
}

class Auth {
  constructor(private secret: string) {}

  async createSession(): Promise<string> {
    const payload = `${Date.now()}.${crypto.randomUUID()}`;
    const sig = await hmacSign(this.secret, payload);
    return `${payload}.${sig}`;
  }

  async verify(token: string | null): Promise<boolean> {
    if (!token) return false;
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = `${parts[0]}.${parts[1]}`;
    const expected = await hmacSign(this.secret, payload);
    const a = hexToBytes(expected);
    const b = hexToBytes(parts[2]);
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    if (diff !== 0) return false;
    const ts = parseInt(parts[0], 10);
    if (!Number.isFinite(ts)) return false;
    const age = Date.now() - ts;
    return age >= 0 && age < SESSION_TTL * 1000;
  }

  sessionCookie(token: string, secure: boolean): string {
    return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL}${secure ? '; Secure' : ''}`;
  }

  clearCookie(): string {
    return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  }
}

/** 会话密钥：优先 env.SESSION_SECRET，否则自动生成并持久化到 D1（isolate 内缓存） */
let secretCache: string | null = null;

async function resolveSecret(env: Env, store: Store): Promise<string> {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  if (secretCache) return secretCache;
  secretCache = await store.getOrCreateSetting('session_secret', () => randomHex(32));
  return secretCache;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // 外部自动化 API（Bearer api_key）—— 必须在静态资源兜底之前拦截
    if (path === '/api/v1/status') {
      return handleWidgetApi(request, env);
    }
    if (path.startsWith('/api/v1/')) {
      return json({ error: 'Not Found' }, 404);
    }

    const action = url.searchParams.get('action') || '';

    // 静态资源优先，未命中的请求才落到后面的 API 处理（避免每个 CSS/JS 请求都触碰 D1）
    if (!action) {
      const assetRes = await serveAsset(env, request);
      if (assetRes) return assetRes;
    }

    const store = new Store(env.DB);
    await store.ensureSchema().catch(() => {});
    const monitor = new Monitor(store);

    const auth = new Auth(await resolveSecret(env, store));
    const isSecure = url.protocol === 'https:';

    try {
      // ---- 公开接口 ----
      if (action === 'check_init') {
        try {
          const settings = await store.getAllSettings();
          return json({ initialized: store.isInitialized(settings) });
        } catch (e: any) {
          return json({ error: '数据库连接失败: ' + (e?.message || e) + ' (请确认 D1 数据库已创建且 wrangler.toml 的 database_id 已正确填写)' }, 500);
        }
      }

      if (action === 'setup') {
        if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
        const settings = await store.getAllSettings();
        if (store.isInitialized(settings)) {
          return json({ success: false, message: 'System already initialized' }, 403);
        }
        const data: any = await request.json();
        try {
          await saveConfig(store, data, { isSetup: true });
          const token = await auth.createSession();
          return json({ success: true }, 200, { 'Set-Cookie': auth.sessionCookie(token, isSecure) });
        } catch (e: any) {
          return json({ success: false, message: e?.message || 'Setup failed' });
        }
      }

      if (action === 'login') {
        if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
        const ip = clientIp(request);
        const attempts = await store.getRecentFailedAttempts(ip, 900);
        if (attempts >= 5) {
          await store.addLog('warning', `登录被锁定: IP ${ip} 尝试次数过多`);
          return json({ success: false, message: '错误次数过多，请 15 分钟后再试。' });
        }
        const { password } = (await request.json().catch(() => ({}))) as any;
        const settings = await store.getAllSettings();
        const adminPass = settings['admin_password'] || '';
        // 未初始化时不允许任何密码通过（避免空密码直接登录）
        if (adminPass && typeof password === 'string' && (await safeEqual(password, adminPass))) {
          await store.clearLoginAttempts(ip);
          await store.addLog('info', `管理员登录成功 [IP: ${ip}]`);
          const token = await auth.createSession();
          return json({ success: true }, 200, { 'Set-Cookie': auth.sessionCookie(token, isSecure) });
        }
        await store.recordLoginAttempt(ip);
        await store.addLog('warning', `管理员登录失败 [IP: ${ip}]`);
        return json({ success: false, message: '密码错误' });
      }

      if (action === 'check_login') {
        return json({ logged_in: await auth.verify(getCookie(request, COOKIE_NAME)) });
      }

      // ---- 需鉴权接口 ----
      if (!(await auth.verify(getCookie(request, COOKIE_NAME)))) {
        return json({ error: 'Unauthorized' }, 403);
      }

      switch (action) {
        case 'get_status': {
          // 只读 D1 缓存，不触发阿里云调用（采集由每分钟 cron 负责）
          return json(await monitor.getStatusForFrontend());
        }
        case 'control_instance': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const { id, action: act } = (await request.json()) as any;
          if (!id || !act) return json({ success: false, message: '参数缺失' });
          return json(await monitor.controlInstance(id, act));
        }
        case 'get_config': {
          return json(await getConfigForFrontend(store));
        }
        case 'save_config': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const data = await request.json();
          try {
            await saveConfig(store, data);
            return json({ success: true });
          } catch (e: any) {
            return json({ success: false, message: e?.message || '保存失败' });
          }
        }
        case 'regenerate_api_key': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const apiKey = 'cdt_' + randomHex(24);
          await store.saveSetting('api_key', apiKey);
          await store.addLog('info', 'API Key 已重置');
          return json({ success: true, api_key: apiKey });
        }
        case 'send_test_email': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const { email } = (await request.json()) as any;
          const settings = await store.getAllSettings();
          const result = await new Notifier(settings).sendTestEmail(email || '');
          return json({ success: result === true, message: result === true ? '' : result });
        }
        case 'send_test_telegram': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const { telegram } = (await request.json()) as any;
          const settings = await store.getAllSettings();
          // 前端拿到的是掩码 token，测试时若未重填则回落到库中真实配置
          const result = await new Notifier(settings).sendTestTelegram(sanitizeOverride(telegram, ['token', 'proxy_pass']));
          return json({ success: result === true, message: result === true ? '' : result });
        }
        case 'send_test_webhook': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const { webhook } = (await request.json()) as any;
          const settings = await store.getAllSettings();
          const result = await new Notifier(settings).sendTestWebhook(webhook || {});
          return json({ success: result === true, message: result === true ? '' : result });
        }
        case 'refresh_account': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const { id } = (await request.json()) as any;
          const result = await monitor.refreshAccount(Number(id));
          if (result === false) return json({ success: false, message: 'Refresh failed' });
          if (typeof result === 'object') return json(result);
          return json({ success: true });
        }
        case 'get_logs': {
          const tab = url.searchParams.get('tab') || 'action';
          const types = tab === 'heartbeat' ? ['heartbeat'] : ['info', 'warning'];
          return json({ data: await store.getLogsByTypes(types, 20) });
        }
        case 'clear_logs': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          const { tab } = (await request.json()) as any;
          const types = tab === 'heartbeat' ? ['heartbeat'] : ['info', 'warning', 'error'];
          await store.clearLogsByTypes(types);
          return json({ success: true });
        }
        case 'get_history': {
          const id = Number(url.searchParams.get('id') || 0);
          return json({ data: await monitor.getAccountHistory(id) });
        }
        case 'logout': {
          if (request.method !== 'POST') return json({ success: false, message: 'Method Not Allowed' }, 405);
          return json({ success: true }, 200, { 'Set-Cookie': auth.clearCookie() });
        }
        default:
          return json({ error: 'Not Found', message: `Unknown action: ${action}` }, 404);
      }
    } catch (e: any) {
      // 不把内部堆栈/SQL 细节回传前端
      console.error('[api]', action, e?.stack || e?.message || e);
      return json({ error: 'Internal Server Error' }, 500);
    }
  },

  /** 每分钟触发 — 对应原版 cron monitor.php */
  async scheduled(_event: any, env: Env, ctx: any): Promise<void> {
    ctx.waitUntil(runMonitor(env));
  },
};

/** 外部只读接口：GET /api/v1/status（Authorization: Bearer cdt_xxx） */
async function handleWidgetApi(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET') {
    return json({ error: 'Method Not Allowed' }, 405, { Allow: 'GET' });
  }
  const store = new Store(env.DB);
  await store.ensureSchema().catch(() => {});

  const apiKey = await store.getSetting('api_key');
  if (!apiKey) {
    return json({ error: 'API Key 未生成，请先在面板「系统配置 → API Key」中生成' }, 403);
  }
  const header = request.headers.get('Authorization') || '';
  const provided = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : '';
  if (!(await safeEqual(provided, apiKey))) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const monitor = new Monitor(store);
  return json(await monitor.getWidgetStatus());
}

async function runMonitor(env: Env): Promise<void> {
  const store = new Store(env.DB);
  await store.ensureSchema().catch(() => {});
  const monitor = new Monitor(store);
  try {
    const output = await monitor.monitor();
    console.log('[monitor]', output.replace(/\n/g, ' | ').slice(0, 2000));
  } catch (e: any) {
    console.error('[monitor] error:', e?.message || e);
    try {
      await store.addLog('error', `监控任务异常: ${e?.message || e}`);
    } catch {}
  }
}

function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

/** 读取静态资源（通过 assets 绑定）。成功返回 Response，未命中返回 null */
async function serveAsset(env: Env, request: Request): Promise<Response | null> {
  if (env.ASSETS) {
    const res = await env.ASSETS.fetch(request);
    if (res.ok) return res;
    if (res.status !== 404) return res;
  }
  return null;
}

async function getConfigForFrontend(store: Store): Promise<any> {
  const settings = await store.getAllSettings();
  const accounts = await store.getAccounts();

  // 老版本升级上来的实例可能还没有 API Key，打开设置页时按需生成
  const apiKey = settings['api_key'] || (await store.getOrCreateSetting('api_key', () => 'cdt_' + randomHex(24)));

  const config: any = {
    // 密码永不回传，前端用 has_password 判断是否需要重填
    has_password: !!settings['admin_password'],
    api_key: apiKey,
    traffic_threshold: parseInt(settings['traffic_threshold'] || '95', 10) || 95,
    enable_schedule_email: settings['enable_schedule_email'] === '1',
    shutdown_mode: settings['shutdown_mode'] || 'KeepCharging',
    threshold_action: settings['threshold_action'] || 'stop_and_notify',
    keep_alive: settings['keep_alive'] === '1',
    api_interval: parseInt(settings['api_interval'] || '600', 10) || 600,
    enable_billing: settings['enable_billing'] === '1',
    Notification: {
      email_enabled: settings['notify_email_enabled'] !== '0',
      email: settings['notify_email'] || '',
      host: settings['notify_host'] || '',
      port: parseInt(settings['notify_port'] || '465', 10),
      username: settings['notify_username'] || '',
      password: maskSecret(settings['notify_password']),
      secure: settings['notify_secure'] || 'ssl',
      telegram: {
        enabled: settings['notify_tg_enabled'] === '1',
        token: maskSecret(settings['notify_tg_token']),
        chat_id: settings['notify_tg_chat_id'] || '',
        proxy_type: settings['notify_tg_proxy_type'] || 'none',
        proxy_url: settings['notify_tg_proxy_url'] || '',
      },
      webhook: {
        enabled: settings['notify_wh_enabled'] === '1',
        url: settings['notify_wh_url'] || '',
        method: settings['notify_wh_method'] || 'GET',
        request_type: settings['notify_wh_request_type'] || 'JSON',
        headers: settings['notify_wh_headers'] || '',
        body: settings['notify_wh_body'] || '',
      },
    },
    Accounts: [],
  };

  for (const row of accounts) {
    config.Accounts.push({
      AccessKeyId: row.access_key_id,
      AccessKeySecret: maskSecret(row.access_key_secret),
      regionId: row.region_id,
      instanceId: row.instance_id,
      maxTraffic: row.max_traffic,
      schedule: {
        enabled: row.schedule_enabled == 1,
        startTime: row.start_time,
        stopTime: row.stop_time,
      },
      remark: row.remark || '',
      siteType: row.site_type || 'china',
    });
  }
  return config;
}

/** 测试接口的临时覆盖参数：掩码/空值视为未填写，交给库中配置兜底 */
function sanitizeOverride(obj: any, secretKeys: string[]): any {
  const out: any = { ...(obj || {}) };
  for (const k of secretKeys) {
    const v = out[k];
    if (v === undefined || v === null || v === '' || isMasked(v)) delete out[k];
  }
  return out;
}

/** 掩码/空值 = 不修改，返回 null 表示保留库中原值 */
function pickSecret(incoming: any): string | null {
  if (incoming === undefined || incoming === null || incoming === '') return null;
  if (isMasked(incoming)) return null;
  return String(incoming);
}

async function resolveAccountSecrets(store: Store, incoming: any[]): Promise<any[]> {
  const existing = await store.getAccounts();
  const map = new Map<string, string>();
  for (const row of existing) {
    map.set(`${row.access_key_id}|${row.region_id}|${row.instance_id || ''}`, row.access_key_secret);
  }
  return incoming.map((acc: any) => {
    const key = `${acc.AccessKeyId}|${acc.regionId}|${acc.instanceId || ''}`;
    const kept = map.get(key) || '';
    const secret = pickSecret(acc.AccessKeySecret);
    return { ...acc, AccessKeySecret: secret === null ? kept : secret };
  });
}

async function saveConfig(store: Store, data: any, opts: { isSetup?: boolean } = {}): Promise<void> {
  const existing = await store.getAllSettings();
  const pairs: [string, string | number][] = [];

  // 密码：留空/未提交 = 不修改（避免误清空后系统重新开放初始化向导）
  const pwd = typeof data.admin_password === 'string' ? data.admin_password.trim() : '';
  if (pwd) {
    if (pwd.length < 4) throw new Error('管理员密码至少 4 位');
    pairs.push(['admin_password', pwd]);
  } else if (!existing['admin_password'] || opts.isSetup) {
    throw new Error('管理员密码不能为空');
  }

  pairs.push(
    ['traffic_threshold', data.traffic_threshold ?? 95],
    ['enable_schedule_email', data.enable_schedule_email ? '1' : '0'],
    ['shutdown_mode', data.shutdown_mode || 'KeepCharging'],
    ['threshold_action', data.threshold_action || 'stop_and_notify'],
    ['keep_alive', data.keep_alive ? '1' : '0'],
    ['api_interval', data.api_interval ?? 600],
    ['enable_billing', data.enable_billing ? '1' : '0'],
  );

  const N = data.Notification || {};
  pairs.push(
    ['notify_email_enabled', N.email_enabled ? '1' : '0'],
    ['notify_email', N.email || ''],
    ['notify_host', N.host || ''],
    ['notify_port', N.port ?? 465],
    ['notify_username', N.username || ''],
    ['notify_secure', N.secure || 'ssl'],
  );
  const smtpPass = pickSecret(N.password);
  if (smtpPass !== null) pairs.push(['notify_password', smtpPass]);

  const tg = N.telegram || {};
  pairs.push(
    ['notify_tg_enabled', tg.enabled ? '1' : '0'],
    ['notify_tg_chat_id', tg.chat_id || ''],
    ['notify_tg_proxy_type', tg.proxy_type || 'none'],
    ['notify_tg_proxy_url', tg.proxy_url || ''],
  );
  const tgToken = pickSecret(tg.token);
  if (tgToken !== null) pairs.push(['notify_tg_token', tgToken]);

  const wh = N.webhook || {};
  pairs.push(
    ['notify_wh_enabled', wh.enabled ? '1' : '0'],
    ['notify_wh_url', wh.url || ''],
    ['notify_wh_method', wh.method || 'GET'],
    ['notify_wh_request_type', wh.request_type || 'JSON'],
    ['notify_wh_headers', wh.headers || ''],
    ['notify_wh_body', wh.body || ''],
  );

  await store.saveSettings(pairs);

  // 首次初始化时生成 API Key
  if (!existing['api_key']) {
    await store.getOrCreateSetting('api_key', () => 'cdt_' + randomHex(24));
  }

  // 账号同步
  await store.syncAccounts(await resolveAccountSecrets(store, data.Accounts || []));
}
