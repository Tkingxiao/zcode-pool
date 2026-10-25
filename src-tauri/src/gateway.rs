use crate::store::{self, Paths};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const UPSTREAM: &str = "https://zcode.z.ai/api/v1/zcode-plan/anthropic";
pub const DEFAULT_PORT: u16 = 8899;
const SWITCH_STATUS: [u16; 4] = [401, 402, 403, 429];
const MAX_TRIES: usize = 4;

/// 上游边缘（阿里云 WAF）按**出口**拦下这条通道时回 **405 + HTML 拦截页**，请求根本没进业务服务。
/// 与号无关，两条实测：匿名假 token 照样 405（GET/POST/PUT 全都一样，而同域名的别的路径照常回
/// 404/400）；换一个出口再发同一发，就变成业务侧的 401。
/// 所以 405 **不进 `SWITCH_STATUS`**：换号纯属浪费，接着撞只会让拦得更久（实测三分钟内累计 2870 发）。
/// 改为整条通道熔断，期间连上游都不碰。
const EDGE_COOLDOWN_MS: u64 = 60_000;

/// 这一类状态码表示**这条路**不对（路由被关、方法不被允许、请求形状超限、被合规封掉），
/// 而不是**这个号**不对。撞上就熔断整条通道，别把同一堵墙按号撞一遍。
/// 405 是其中最常见的一个，另外兜进这张表的都是同一种形状，见 `handle_external`。
const PATH_STATUS: [u16; 11] = [404, 405, 406, 410, 411, 413, 414, 415, 451, 501, 505];

/// 上游自己 5xx：整条路都在冒烟，但通常是暂时的 —— 短熔断，恢复得比 405 快。
const UPSTREAM_COOLDOWN_MS: u64 = 15_000;

/// 对话测试最多试几个候选凭证。每一发都是真请求（会占一点点额度），
/// 所以上限压低：现在的号最多 3 个去重后的候选，留一位富余。
const MAX_PROBE_TOKENS: usize = 4;

/// 会话粘性的存活时间与条数上限。上限是防内存无界增长（每个会话一条）。
const STICKY_TTL_MS: u64 = 30 * 60 * 1000;
const STICKY_MAX: usize = 64;

/// 同一个号两次额度重取之间的最小间隔。
const REFRESH_MIN_GAP_MS: u64 = 15_000;

/// 号池眼看要空时，最多愿意同步等这么久逼出真实额度，再决定要不要回 502。
/// 等不到也放行 —— 刷新线程继续在后台跑，绝不把请求挂死。
const EMPTY_WAIT_MS: u64 = 2_000;
const QUOTA_TTL_MS: u64 = 5 * 60 * 1000;

const RATE_TTL_MS: u64 = 5 * 60 * 1000;

/// 401/402/403 的冷却比限流短：号只有一个的时候，5 分钟冻结等于把整个池子判死；
/// 一分钟足够让它自己回到候选里，真死掉的凭证也会反复冷却、不会每发都试。
const AUTH_COOLDOWN_MS: u64 = 60_000;

pub const POLICY_EXPIRE: &str = "expire_first";
pub const POLICY_MOST_LEFT: &str = "most_left";
pub const POLICY_PINNED: &str = "pinned";

pub const MODEL_AUTO: &str = "auto";
pub const MODEL_PINNED: &str = "pinned";

pub const EXTERNAL_MODELS: [&str; 2] = ["GLM-5.3-Flash", "GLM-5.3"];

const MINT_PAGE: &str = include_str!("../assets/mint.html");

const CHAT_PAGE: &str = include_str!("../assets/chat.html");

const PROXY_PAGE: &str = include_str!("../assets/proxy.html");

const CLIENT_HEADERS: [(&str, &str); 17] = [
    ("anthropic-version", "2023-06-01"),
    ("content-type", "application/json"),
    ("http-referer", "https://zcode.z.ai"),
    ("user-agent", "@UA@"),
    ("x-client-language", "zh-CN"),
    ("x-client-timezone", "Asia/Shanghai"),
    ("x-os-category", "windows"),
    ("x-os-version", "10.0.26200"),
    ("x-platform", "win32-x64"),
    ("x-release-channel", "production"),
    ("x-title", "Z Code@electron"),
    ("x-zcode-agent", "glm"),
    ("x-zcode-app-version", "@VER@"),
    ("x-zcode-session-type", "main"),
    ("accept", "*/*"),
    ("accept-language", "*"),
    ("sec-fetch-mode", "cors"),
];

const CAPTCHA_REGION: &str = "cn";

/// 请求头里的版本号是**客户端版本**（上游会看）。
/// 以前这里是写死的 `3.14.3` —— 客户端一升到 3.14.4，上游就把我们当旧版本挡了。
/// 现在统一从 `quota::zcode_app_version()` 取（它先查注册表，查不到用常量兜底）。
fn client_headers() -> Vec<(&'static str, String)> {
    let ver = crate::quota::zcode_app_version();
    CLIENT_HEADERS
        .iter()
        .map(|(k, v)| {
            let v = match *v {
                "@UA@" => format!("ZCode/{ver} ai-sdk/provider-utils/4.0.27 runtime/node.js/24"),
                "@VER@" => ver.clone(),
                other => other.to_string(),
            };
            (*k, v)
        })
        .collect()
}

/// 反代出站用的 agent：带上 `relay_proxy`，代理配置坏了就退回直连并记一行。
/// `read_secs` 是读超时 —— 真实转发要容忍长回答（600s），对话测试不该等人十分钟。
fn relay_agent(proxy_url: Option<&str>, read_secs: u64) -> ureq::Agent {
    let mut ab = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(read_secs));
    if let Some(u) = proxy_url {
        match ureq::Proxy::new(u) {
            Ok(px) => ab = ab.proxy(px),
            Err(e) => crate::flowlog::log("relay", "proxy-bad", &format!("{u}：{e} —— 这一发按直连走")),
        }
    }
    ab.build()
}

/// 出站请求的头。真实转发与「对话测试」**共用这一个函数**：少任何一个头，上游都可能
/// 把请求判成异常（实测身份段/头不齐回 405 `{"code":3012}`），那测出来的结论就不作数。
fn set_relay_headers(req: ureq::Request, token: &str) -> ureq::Request {
    let mut r = req;
    for (k, v) in client_headers() {
        r = r.set(k, &v);
    }
    r.set("authorization", &format!("Bearer {}", token))
        .set("x-api-key", token)
        // 注：以前这里还有 x-aliyun-captcha-verify-param / -region 两个头，
        // 2026-09-30 起不再发（上游已关闭模型请求的验证码校验，见 handle_external 里的说明）。
        .set("x-query-id", &uuid::Uuid::now_v7().to_string())
        .set("x-request-id", &uuid::Uuid::new_v4().to_string())
        .set("x-session-id", &uuid::Uuid::new_v4().to_string())
        .set("x-zcode-trace-id", &uuid::Uuid::new_v4().to_string())
}

const METER_WINDOW_MS: u64 = 15_000;

const PROBE_EVERY_MS: u64 = 90_000;

const PROBE_HISTORY: usize = 24;
const PARAM_PRE: usize = 1;
const PARAM_MAX_POOL: usize = 4;
const PARAM_MAX_AGE_MS: u64 = 90_000;
const PARAM_WAIT_MS: u64 = 25_000;
const ACTIVE_WINDOW_MS: u64 = 180_000;
const INFLIGHT_TTL_MS: u64 = 30_000;

fn quota_cache_file(paths: &Paths) -> std::path::PathBuf {
    paths.store_dir().join("quota-cache.json")
}

const QUOTA_DISK_TTL_MS: u64 = 10 * 60 * 1000;

type QuotaSnap = (Vec<(String, (u64, crate::quota::QuotaOverview))>, Option<String>, usize);

fn quota_snapshot(g: &Inner) -> QuotaSnap {
    let now = now_ms();
    (
        g.quota
            .iter()
            .filter(|(_, (at, _))| now.saturating_sub(*at) <= QUOTA_DISK_TTL_MS)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        g.last_refresh.clone(),
        g.quota_total,
    )
}

fn write_quota_cache(paths: &Paths, snap: QuotaSnap) {
    let (items, last_refresh, total) = snap;
    if items.is_empty() {
        return;
    }
    let mut entries = serde_json::Map::new();
    for (id, (at, ov)) in items {
        let Ok(v) = serde_json::to_value(&ov) else { continue };
        entries.insert(id, json!({ "at": at, "ov": v }));
    }
    let v = json!({ "entries": entries, "lastRefresh": last_refresh, "total": total });
    let p = quota_cache_file(paths);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = p.with_extension("json.tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        if std::fs::rename(&tmp, &p).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

fn read_quota_cache(paths: &Paths) -> QuotaSnap {
    let Ok(s) = std::fs::read_to_string(quota_cache_file(paths)) else {
        return (Vec::new(), None, 0);
    };
    let Ok(v) = serde_json::from_str::<Value>(&s) else {
        return (Vec::new(), None, 0);
    };
    let now = now_ms();
    let mut out = Vec::new();
    if let Some(entries) = v.get("entries").and_then(|x| x.as_object()) {
        for (id, e) in entries {
            let at = e.get("at").and_then(|x| x.as_u64()).unwrap_or(0);
            if now.saturating_sub(at) > QUOTA_DISK_TTL_MS {
                continue;
            }
            let Some(ov) = e.get("ov") else { continue };
            let Ok(ov) = serde_json::from_value::<crate::quota::QuotaOverview>(ov.clone()) else {
                continue;
            };
            out.push((id.clone(), (at, ov)));
        }
    }
    let lr = v.get("lastRefresh").and_then(|x| x.as_str()).map(str::to_string);
    let total = v.get("total").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    (out, lr, total)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

struct Route {
    account: String,
    model: String,
    tries: usize,
}

#[derive(Default)]
struct Inner {
    running: bool,
    port: u16,
    served: u64,
    switched: u64,
    client_account: Option<String>,
    last_route: Option<Route>,
    stop: Option<Arc<AtomicBool>>,

    server: Option<Arc<tiny_http::Server>>,

    serving: Option<Arc<AtomicBool>>,
    quota: HashMap<String, (u64, crate::quota::QuotaOverview)>,

    /// 粘性：会话指纹 → `(号 id, 最后使用时刻)`。
    /// 以前是全局单值 `Option<String>`，等于把所有并发都钉在同一个号上，
    /// 别的号的余量永远用不上。
    sticky: HashMap<String, (String, u64)>,

    /// 待重取额度的号：本地扣减到 0、上游拒绝、缓存缺失都会塞这里，由请求入口排空。
    quota_dirty: Vec<String>,

    /// 每个号上一次**开始**重取额度的时刻 —— 防同一个号被反复刷
    quota_refresh_at: HashMap<String, u64>,

    refreshing: bool,
    last_refresh: Option<String>,
    last_billing: Option<String>,
    policy: String,
    pinned: Option<String>,
    model_mode: String,

    model_pinned: Option<String>,

    /// 反代出站的代理（空 = 直连）。见 `Settings::relay_proxy`
    relay_proxy: Option<String>,
    quota_total: usize,
    last_failed: Vec<String>,

    external: bool,

    params: Vec<(String, String, u64)>,

    waiters: usize,

    inflight: Vec<u64>,

    last_use: u64,
    mints: u64,
    mint_times: Vec<u64>,

    bytes_out: u64,

    tokens_sum: u64,

    last_gen_tps: Option<f64>,

    meter: Vec<(u64, u64, u64)>,

    health: HashMap<String, Health>,

    last_ttfb_ms: Option<u64>,
    last_total_ms: Option<u64>,

    bind: String,

    keys: Vec<String>,

    model_map: std::collections::BTreeMap<String, String>,

    /// 号级冷却：账号 id → **解冻时刻**（不是打标时刻）。过期即自动重新入选，
    /// `unfreeze` 可以手动提前清。
    ///
    /// 「额度用尽」以前想另存一张 `(号, 模型档)` 表，但它从来没有写入点 —— 没额度的号
    /// 在 `candidates` 里直接按实时额度筛掉了，那张表已删。
    blocked: HashMap<String, u64>,

    /// 上游通道熔断状态（与号无关，整条通道共用一个）
    edge: Edge,
}

#[derive(Clone, Default)]
pub struct Gateway {
    inner: Arc<Mutex<Inner>>,

    app: Arc<std::sync::OnceLock<tauri::AppHandle>>,
}

/// 通道级熔断的状态机。刻意不依赖 `Gateway`/tauri 类型 —— 只要测试里出现
/// `Gateway`，`OnceLock<AppHandle>` 的 drop glue 就会把整套 tauri/Win32 入口拉进
/// 测试二进制，而它没带应用清单，进程启动即 STATUS_ENTRYPOINT_NOT_FOUND（实测踩过）。
#[derive(Default)]
struct Edge {
    /// 解冻时刻（0 = 没熔）
    until: u64,
    /// 熔断期内是否已经记过日志
    warned: bool,
}

impl Edge {
    fn trip(&mut self, now: u64, ms: u64) {
        self.until = now + ms;
        self.warned = false;
    }

    /// 手动解除，返回解除时还剩多少毫秒
    fn reset(&mut self, now: u64) -> u64 {
        let left = self.until.saturating_sub(now);
        self.until = 0;
        self.warned = false;
        left
    }

    fn left(&self, now: u64) -> u64 {
        self.until.saturating_sub(now)
    }

    /// 熔断中就给出 `(还剩多久, 是不是这一轮第一次)`；第一次那次为 true ——
    /// 日志只在那一次打，否则客户端每秒重试就是每秒一行（旧版实测 3 分钟 2870 行）。
    fn waiting(&mut self, now: u64) -> Option<(u64, bool)> {
        let left = self.until.saturating_sub(now);
        if left == 0 {
            return None;
        }
        let first = !self.warned;
        self.warned = true;
        Some((left, first))
    }
}

struct Candidate {
    id: String,
    name: String,
    token: String,
    mid: String,
    expire: Option<String>,
    left: f64,
}

impl Gateway {
    pub fn new() -> Self {
        let g = Self::default();
        {
            let mut i = g.inner.lock().unwrap();
            i.bind = "127.0.0.1".to_string();
            i.policy = POLICY_EXPIRE.to_string();
            i.model_mode = MODEL_AUTO.to_string();
        }
        g
    }

    pub fn set_app(&self, app: tauri::AppHandle) {
        let _ = self.app.set(app);
    }

    fn app(&self) -> Option<tauri::AppHandle> {
        self.app.get().cloned()
    }

    fn sync_exe(&self) {
        if let Some(app) = self.app() {
            crate::rebuild_tray(&app);
            crate::emit_state_changed(&app);
        }
    }

    pub fn console_status(&self, paths: &Paths) -> Value {
        let accs = store::list_accounts(paths).unwrap_or_default();
        let accounts: Vec<String> = accs.iter().map(|a| a.name.clone()).collect();
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.meter.retain(|s| now.saturating_sub(s.0) < METER_WINDOW_MS);
        let (dt, dbytes, dtok) = meter_delta(&g);

        let (tps, tps_est) = if dt <= 0.0 {
            (0.0, false)
        } else if dtok > 0 {
            (dtok as f64 / dt, false)
        } else {
            (dbytes as f64 / 4.0 / dt, true)
        };
        let bps = if dt <= 0.0 { 0.0 } else { dbytes as f64 / dt };

        let frozen: serde_json::Map<String, Value> = {
            let mut m = serde_json::Map::new();
            for (id, t) in g.blocked.iter() {
                if *t > now {
                    m.insert(id.clone(), json!("冷却"));
                }
            }
            m
        };
        let generating = g
            .meter
            .last()
            .map(|s| now.saturating_sub(s.0) < 2500)
            .unwrap_or(false);
        let routing = g
            .last_route
            .as_ref()
            .map(|r| r.account.clone())
            .unwrap_or_else(|| "-".into());
        let routed = g
            .last_route
            .as_ref()
            .map(|r| json!({ "account": r.account, "model": r.model, "tries": r.tries }));
        json!({
            "running": g.running,
            "port": g.port,
            "external": g.external,
            "served": g.served,
            "switched": g.switched,
            "models": EXTERNAL_MODELS,
            "mint": mint_stats(&g),
            "routed": routed,
            "routing": routing,
            "accounts": accounts,

            "channels": accs.iter().map(|a| json!({
                "id": a.id,
                "name": a.name,
                "health": g.health.get(&a.id).map(|h| h.json()),
                "frozen": frozen.get(&a.id),
            })).collect::<Vec<_>>(),
            "bytes": g.bytes_out,
            "tokens": g.tokens_sum,
            "lastTps": g.last_gen_tps,
            "tps": (tps * 10.0).round() / 10.0,
            "tpsEstimated": tps_est,
            "bps": (bps * 10.0).round() / 10.0,
            "generating": generating,
            "ttfbMs": g.last_ttfb_ms,
            "totalMs": g.last_total_ms,
            // 反代对外冒充的 ZCode 客户端版本（从安装的 exe 里读，读不到才用兜底常量）
            "zcodeVersion": crate::quota::zcode_app_version(),
            "relayProxy": g.relay_proxy,
            "bind": g.bind,
            "keys": g.keys,
            "modelMap": g.model_map,
            "lanHost": lan_host(),
            "policy": g.policy,
            "pinned": g.pinned,
            "modelMode": g.model_mode,
            "modelPinned": g.model_pinned,
            "health": g.health.iter().map(|(k, v)| (k.clone(), v.json())).collect::<serde_json::Map<String, Value>>(),
            "frozen": frozen,

            "quotaAccounts": g.quota.len(),
            "quotaTotal": g.quota_total,
            "quotaFailed": g.last_failed.clone(),
            "lastRefresh": g.last_refresh.clone(),
        })
    }

    pub fn status(&self, paths: &Paths) -> Value {
        let next_up = if self.inner.lock().unwrap().last_route.is_none() {
            self.next_up(paths)
        } else {
            None
        };
        let live_id = if self.inner.lock().unwrap().client_account.is_none() {
            live_account_id(paths)
        } else {
            None
        };
        let g = self.inner.lock().unwrap();
        let client_id = g.client_account.clone().or(live_id);
        let route_id = g
            .last_route
            .as_ref()
            .map(|r| r.account.clone())
            .or_else(|| next_up.clone());
        json!({
            "running": g.running,
            "port": g.port,
            "defaultPort": DEFAULT_PORT,
            "served": g.served,
            "switched": g.switched,
            "upstream": UPSTREAM,
            "clientAccount": client_id.clone(),
            "routedAccount": g.last_route.as_ref().map(|r| r.account.clone()),
            "routedModel": g.last_route.as_ref().map(|r| r.model.clone()),
            "routedTries": g.last_route.as_ref().map(|r| r.tries),
            "nextAccount": next_up,
            "quotaAccounts": g.quota.len(),
            "quotaTotal": g.quota_total,
            "quotaFailed": g.last_failed.clone(),
            "lastRefresh": g.last_refresh,
            "lastBilling": g.last_billing,
            "routedQuota": quota_rows_for(&g, route_id.as_deref()),
            "clientQuota": quota_rows_for(&g, client_id.as_deref()),
            "blocked": g.blocked.values().filter(|t| **t > now_ms()).count(),
            "edgeLeft": g.edge.left(now_ms()),
            "policy": g.policy,
            "pinned": g.pinned,
            "sticky": g.sticky.values().map(|(id, _)| id.clone()).collect::<std::collections::BTreeSet<_>>(),
            "stickySessions": g.sticky.len(),
            "modelMode": g.model_mode,
            "modelPinned": g.model_pinned,
            "models": models_seen(&g.quota),
            "external": g.external,
            "externalModels": EXTERNAL_MODELS,
            "mint": mint_stats(&g),
        })
    }

    fn next_up(&self, paths: &Paths) -> Option<String> {
        let ms = {
            let g = self.inner.lock().unwrap();
            models_seen(&g.quota)
        };
        for m in ms {
            if let Some(c) = self.sticky_order(self.candidates(paths, &m), "").into_iter().next() {
                return Some(c.id);
            }
        }
        None
    }

    pub fn warm_quota(
        &self,
        paths: &Paths,
        max_passes: usize,
        progress: impl Fn(Value),
    ) -> Value {
        let ids: Vec<String> = store::list_accounts(paths)
            .map(|v| v.into_iter().map(|a| a.id).collect())
            .unwrap_or_default();
        let total = ids.len();
        let mut pass = 0usize;
        let mut have = 0usize;
        for p in 1..=max_passes.max(1) {
            pass = p;
            let _ = self.refresh_quota(paths, false);
            have = {
                let g = self.inner.lock().unwrap();
                ids.iter().filter(|i| g.quota.contains_key(*i)).count()
            };
            progress(json!({ "pass": p, "have": have, "total": total }));
            if have >= total {
                break;
            }
            if p < max_passes {
                std::thread::sleep(Duration::from_millis(900));
            }
        }
        let failed = self.inner.lock().unwrap().last_failed.clone();
        json!({ "have": have, "total": total, "passes": pass,
                "complete": have >= total, "failed": failed })
    }

    pub fn set_policy(&self, policy: String, pinned: Option<String>) -> Result<(), String> {
        if !matches!(policy.as_str(), POLICY_EXPIRE | POLICY_MOST_LEFT | POLICY_PINNED) {
            return Err(crate::i18n::tr("err.gw.bad_policy"));
        }
        let mut g = self.inner.lock().unwrap();
        g.policy = policy;
        g.pinned = pinned.filter(|p| !p.trim().is_empty());
        g.sticky.clear();
        Ok(())
    }

    pub fn set_model_mode(&self, paths: &Paths, mode: String, pinned: Option<String>) -> Result<(), String> {
        if !matches!(mode.as_str(), MODEL_AUTO | MODEL_PINNED) {
            return Err("模型策略只有「自动回退」和「指定模型」两种".into());
        }
        let pin = pinned.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if mode == MODEL_PINNED && pin.is_none() {
            return Err("选了「指定模型」就得挑一个模型".into());
        }
        {
            let mut g = self.inner.lock().unwrap();
            g.model_mode = mode.clone();
            g.model_pinned = pin.clone();
        }
        if let Err(e) = store::set_relay_model_policy(paths, &mode, pin.as_deref()) {
            crate::flowlog::log("relay", "model-mode-persist-fail", &e);
        }
        crate::flowlog::log("relay", "model-mode", &format!(
            "{mode}{}", pin.map(|p| format!(" 指定={p}")).unwrap_or_default()));
        Ok(())
    }

    fn mark_blocked(&self, id: &str, ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.blocked.retain(|_, t| *t > now);
        let cur = g.blocked.get(id).copied().unwrap_or(0);
        g.blocked.insert(id.to_string(), cur.max(now + ms));
    }

    /// 熔断整条上游通道 `ms`：期间 `handle_external` 直接回 503，一个请求都不往上游发。
    fn edge_trip(&self, ms: u64) {
        self.inner.lock().unwrap().edge.trip(now_ms(), ms);
    }

    /// 手动解除通道熔断（换了出口/网络之后不想干等 TTL）。返回解除时还剩多少毫秒。
    fn edge_reset(&self) -> u64 {
        self.inner.lock().unwrap().edge.reset(now_ms())
    }

    /// 立刻重取这些号的额度：单号粒度、去重节流、跑在后台线程 —— 不挡请求路径。
    ///
    /// `wait_ms > 0` 只用在一处：候选已经空了、必须当场决定是不是回 502。等不到也照样
    /// 返回 0，线程继续在后台跑，绝不把请求挂死（返回 0 不代表失败）。
    fn refresh_accounts(&self, paths: &Paths, ids: Vec<String>, wait_ms: u64, reason: &'static str) -> usize {
        let now = now_ms();
        let mut todo: Vec<String> = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            // 只留还在冷却期内的；过期的清掉，这张表不会无界增长
            g.quota_refresh_at.retain(|_, t| now.saturating_sub(*t) < REFRESH_MIN_GAP_MS * 4);
            for id in ids {
                if g.quota_refresh_at.contains_key(&id) {
                    continue;
                }
                g.quota_refresh_at.insert(id.clone(), now);
                todo.push(id);
            }
        }
        if todo.is_empty() {
            return 0;
        }
        crate::flowlog::log("relay", "quota-refresh", &format!("为 {} 个号重取额度（{reason}）", todo.len()));
        let inner = self.inner.clone();
        let p2 = Paths { home: paths.home.clone() };
        let (tx, rx) = std::sync::mpsc::channel::<usize>();
        std::thread::spawn(move || {
            let mut n = 0usize;
            for id in &todo {
                match store::account_quota(&p2, id) {
                    Ok(ov) => {
                        inner.lock().unwrap().quota.insert(id.clone(), (now_ms(), ov));
                        n += 1;
                    }
                    Err(e) => crate::flowlog::log(
                        "relay",
                        "quota-refresh",
                        &format!("{id} 重取失败：{}", crate::quota::body_snippet(&e)),
                    ),
                }
            }
            let _ = tx.send(n);
        });
        if wait_ms == 0 {
            return 0;
        }
        rx.recv_timeout(Duration::from_millis(wait_ms)).unwrap_or(0)
    }

    /// 排空「该重取额度」队列 —— 本地扣到 0、上游拒绝、缓存缺失都会往里塞。
    /// 放在请求入口跑：后台刷，这一发不挡。
    fn drain_quota_dirty(&self, paths: &Paths) {
        let ids = {
            let mut g = self.inner.lock().unwrap();
            std::mem::take(&mut g.quota_dirty)
        };
        if ids.is_empty() {
            return;
        }
        self.refresh_accounts(paths, ids, 0, "待确认队列");
    }

    /// 清掉某个号「上次试通的凭证」指纹（只在真存着时才落一次盘）。
    fn drop_plan_hint(&self, paths: &Paths, id: &str) {
        let mut acc = match store::load_account(paths, id) {
            Ok(a) => a,
            Err(_) => return,
        };
        if acc.plan_token.take().is_none() {
            return;
        }
        match store::save_account(paths, &acc) {
            Ok(()) => crate::flowlog::log("relay", "token-hint", &format!("{id} 记住的凭证回 401，已清掉提示、回到默认顺序")),
            Err(e) => crate::flowlog::log("relay", "token-hint", &format!("{id} 清提示失败：{e}")),
        }
    }

    /// 取号 / 同步之后**后台**立刻试一次：把这个号真正能用的那一份凭证定下来。
    ///
    /// 不能留给第一发真实请求去猜 —— 实测 `candidate_tokens` 会把 provider 的
    /// coding-plan apiKey 排到第一位，而那条端点不认它，于是三个号一上就被 401。
    /// 放后台是因为「添加账号」的流程不该被一次模型请求卡住几秒到几十秒。
    pub fn probe_after_capture(&self, paths: &Paths, id: &str) {
        let me = self.clone();
        let p = Paths { home: paths.home.clone() };
        let id = id.to_string();
        std::thread::spawn(move || {
            let r = chat_test(&me, &p, &id);
            let ok = r.get("ok").and_then(Value::as_bool).unwrap_or(false);
            crate::flowlog::log(
                "relay",
                "probe-after-capture",
                &format!("{} {}", id, if ok { "已自动定下可用凭证" } else { "试完所有凭证都没出话 —— 这个号可能不能用于反代" }),
            );
        });
    }

    fn probe_one(&self, paths: &Paths, id: &str) -> Result<u64, String> {
        let secret = crate::zcrypto::default_secret(&paths.home);
        let acc = store::load_account(paths, id)?;
        let tokens = crate::quota::candidate_tokens(&acc.credentials, acc.config.as_ref(), &secret);
        if tokens.is_empty() {
            return Err("没有可用凭证".into());
        }
        let mid = store::account_mid(paths, id).ok();
        let t0 = now_ms();
        let r = crate::quota::query_quota_mid(&tokens, mid.as_deref());
        let ms = now_ms().saturating_sub(t0);
        let out = r.map(|_| ms).map_err(|e| e.chars().take(120).collect::<String>());
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        let h = g.health.entry(id.to_string()).or_default();
        h.last_at = Some(now);
        h.last_ms = out.as_ref().ok().copied();
        match &out {
            Ok(_) => {
                h.ok += 1;
                h.streak = 0;
                h.last_err.clear();
            }
            Err(e) => {
                h.fail += 1;
                h.streak = h.streak.saturating_add(1);
                h.last_err = e.clone();
            }
        }
        h.history.push((now, out.as_ref().ok().copied()));
        while h.history.len() > PROBE_HISTORY {
            h.history.remove(0);
        }
        out
    }

    fn probe_tick(&self, paths: &Paths) {
        let accounts = store::list_accounts(paths).unwrap_or_default();
        if accounts.is_empty() {
            return;
        }
        let pick = {
            let g = self.inner.lock().unwrap();
            accounts
                .iter()
                .map(|a| (g.health.get(&a.id).and_then(|h| h.last_at).unwrap_or(0), a.id.clone()))
                .min()
                .map(|(_, id)| id)
        };
        let Some(id) = pick else { return };

        let jitter = (now_ms() % (PROBE_EVERY_MS * 8 / 10)) / 2;
        std::thread::sleep(Duration::from_millis(jitter));
        match self.probe_one(paths, &id) {
            Ok(ms) => crate::flowlog::log("relay", "probe-ok", &format!("{id} {ms}ms")),
            Err(e) => crate::flowlog::log("relay", "probe-fail", &format!("{id} {e}")),
        }
    }

    pub fn set_external_and_run(&self, paths: &Paths, on: bool) -> Result<Value, String> {
        if on {
            let running = self.inner.lock().unwrap().running;
            if !running {
                let port = self.port_or_default();
                self.start(Paths { home: paths.home.clone() }, port)?;
            }
        }
        self.set_external(on);

        if let Err(e) = store::set_relay_external(paths, on) {
            crate::flowlog::log("relay", "external-persist-fail", &e);
        }
        if !on {
            self.stop();
        }
        Ok(self.console_status(paths))
    }

    fn port_or_default(&self) -> u16 {
        match self.inner.lock().unwrap().port {
            0 => DEFAULT_PORT,
            p => p,
        }
    }

    pub fn restore_persisted(&self, paths: &Paths) {
        let st = store::load_settings(paths);

        let cached = read_quota_cache(paths);
        let mut g = self.inner.lock().unwrap();
        if let Some(b) = st.relay_bind {
            g.bind = b;
        }
        if let Some(k) = st.relay_keys {
            g.keys = k;
        }
        if let Some(m) = st.model_map {
            g.model_map = m;
        }
        if let Some(m) = st.relay_model_mode {
            if m == MODEL_AUTO || m == MODEL_PINNED {
                g.model_mode = m;
            }
        }
        if let Some(p) = st.relay_model_pinned {
            g.model_pinned = Some(p).filter(|x| !x.trim().is_empty());
        }
        g.relay_proxy = st.relay_proxy.filter(|x| !x.trim().is_empty());
        if !cached.0.is_empty() {
            for (id, (at, ov)) in cached.0 {
                g.quota.insert(id, (at, ov));
            }
            g.quota_total = cached.2.max(g.quota.len());
            g.last_refresh = cached.1;
            crate::flowlog::log("relay", "quota-cache-load", &format!("从盘上恢复了 {} 个号的额度", g.quota.len()));
        }
    }

    pub fn set_model_map(&self, paths: &Paths, from: &str, to: &str) -> Result<Value, String> {
        let from = from.trim();
        if from.is_empty() {
            return Err("请求的模型名不能空".into());
        }
        let mut g = self.inner.lock().unwrap();
        if to.trim().is_empty() {
            g.model_map.remove(from);
        } else {
            let to = to.trim();
            if to == from {
                return Err("映射到自己是多余的".into());
            }
            g.model_map.insert(from.to_string(), to.to_string());
        }
        let m = g.model_map.clone();
        drop(g);
        store::set_model_map(paths, &m)?;
        Ok(self.console_status(paths))
    }

    pub fn set_bind(&self, paths: &Paths, bind: &str) -> Result<Value, String> {
        let bind = bind.trim().to_string();
        let loopback = matches!(bind.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !loopback {
            let n = self.inner.lock().unwrap().keys.len();
            if n == 0 {
                return Err("绑到非本机地址之前，先创建一个 API Key —— 否则同网段的人都能用你的号池".into());
            }
        }
        if let Err(e) = store::set_relay_bind(paths, &bind) {
            crate::flowlog::log("relay", "bind-persist-fail", &e);
        }
        {
            let mut g = self.inner.lock().unwrap();
            g.bind = bind.clone();
        }

        crate::flowlog::log(
            "relay",
            "bind-set",
            if loopback { "监听策略 -> 仅本机" } else { "监听策略 -> 局域网可访问（要带 key）" },
        );
        Ok(self.console_status(paths))
    }

    pub fn key_add(&self, paths: &Paths, want: &str) -> Result<String, String> {
        let want = want.trim();
        let k = if want.is_empty() {

            let mut h = Sha256::new();
            h.update(uuid::Uuid::new_v4().as_bytes());
            h.update(uuid::Uuid::new_v4().as_bytes());
            h.update(now_ms().to_le_bytes());
            format!("zp-{}", hex(&h.finalize())[..32].to_string())
        } else {

            if !want.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err("只能用字母、数字、- 和 _".into());
            }
            want.to_string()
        };
        let mut g = self.inner.lock().unwrap();
        if g.keys.iter().any(|x| x == &k) {
            return Err("这个 key 已经存在了".into());
        }
        g.keys.push(k.clone());
        let keys = g.keys.clone();
        drop(g);
        store::set_relay_keys(paths, &keys)?;
        Ok(k)
    }

    pub fn key_del(&self, paths: &Paths, key: &str) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        g.keys.retain(|k| k != key);
        let keys = g.keys.clone();
        drop(g);
        store::set_relay_keys(paths, &keys)
    }

    pub fn set_port(&self, paths: &Paths, port: u16) -> Result<Value, String> {
        if port < 1024 {
            return Err("端口要 >= 1024".into());
        }
        let old = self.port_or_default();
        if port == old {
            return Ok(self.console_status(paths));
        }

        if let Err(e) = store::set_relay_port(paths, port) {
            crate::flowlog::log("relay", "port-persist-fail", &e);
        }
        let was_on = self.inner.lock().unwrap().external;
        self.stop();

        for _ in 0..12 {
            if !port_answers(old) {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        if port_answers(old) {
            self.set_external(was_on);
            crate::flowlog::log("relay", "port-stuck", &format!("旧端口 {old} 停不掉，没敢切"));
            return Err(format!(
                "旧端口 {old} 停不掉（服务其实还在，能正常用）—— 换端口需要**重启一次工具**，重启后直接就是新端口"
            ));
        }
        if let Err(e) = self.start(Paths { home: paths.home.clone() }, port) {
            let _ = self.start(Paths { home: paths.home.clone() }, old);
            self.set_external(was_on);
            return Err(format!("新端口起不来（{e}），已退回 {old}"));
        }
        self.set_external(was_on);
        Ok(self.console_status(paths))
    }

    /// 手动提前解冻一个号：清掉号级冷却标记 + 把「连续失败」计数归零，返回清掉的条数。
    /// 不解通道熔断 —— 那是另一层，见 `edge_reset`。
    pub fn unfreeze(&self, id: &str) -> usize {
        let mut g = self.inner.lock().unwrap();
        let before = g.blocked.len();
        g.blocked.remove(id);
        let n = before - g.blocked.len();
        if let Some(h) = g.health.get_mut(id) {
            h.streak = 0;
        }
        n
    }

    pub fn set_external(&self, on: bool) {
        self.inner.lock().unwrap().external = on;
    }

    /// 从取码池里取一个一次性验证码。
    ///
    /// ⚠ 2026-09-30 起**没有调用点**了：实测上游不再要求模型请求带验证码（见 `handle_external`
    /// 里那段说明）。保留在这里是为了万一上游改回去时能一键恢复，不是漏删。
    #[allow(dead_code)]
    fn take_param(&self) -> Result<(String, String), String> {
        let t0 = now_ms();
        {
            let mut g = self.inner.lock().unwrap();
            g.waiters += 1;

            g.last_use = t0;
        }
        let deadline = t0 + PARAM_WAIT_MS;
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                let now = now_ms();
                let cut = now.saturating_sub(PARAM_MAX_AGE_MS);
                g.params.retain(|p| p.2 >= cut);
                if !g.params.is_empty() {
                    let (param, region, _) = g.params.remove(0);
                    g.last_use = now;
                    g.waiters = g.waiters.saturating_sub(1);
                    return Ok((param, region));
                }
            }
            if now_ms() >= deadline {
                let mut g = self.inner.lock().unwrap();
                g.waiters = g.waiters.saturating_sub(1);
                return Err(crate::i18n::tr("err.gw.no_param"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn put_param(&self, param: String, region: String) -> usize {
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.params.push((param, region, now));
        g.mints += 1;
        g.mint_times.push(now);
        let cut = now.saturating_sub(10 * 60 * 1000);
        g.mint_times.retain(|t| *t >= cut);
        if !g.inflight.is_empty() {
            g.inflight.pop(); 
        }
        g.params.len()
    }

    fn want_mint(&self, wait: bool) -> Value {
        let deadline = now_ms() + if wait { PARAM_WAIT_MS } else { 0 };
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                let now = now_ms();
                let cut = now.saturating_sub(PARAM_MAX_AGE_MS);
                g.params.retain(|p| p.2 >= cut);
                g.inflight.retain(|t| now.saturating_sub(*t) < INFLIGHT_TTL_MS);
                let n = g.params.len();
                let active = now.saturating_sub(g.last_use) < ACTIVE_WINDOW_MS;
                let want = g.waiters + if active { PARAM_PRE } else { 0 };

                let mut short = want as i64 - n as i64 - g.inflight.len() as i64;
                if n >= PARAM_MAX_POOL {
                    short = 0; 
                }
                if short > 0 {
                    g.inflight.push(now);
                    return json!({ "want": true, "pool": n, "target": n + short as usize });
                }
                if now_ms() >= deadline {
                    return json!({ "want": false, "pool": n, "target": n });
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn start(&self, paths: Paths, port: u16) -> Result<(), String> {
        {
            let g = self.inner.lock().unwrap();
            if g.running {
                return Err(crate::i18n::tr("err.gw.already_running"));
            }
        }

        let server = tiny_http::Server::http(("0.0.0.0", port))
            .map_err(|e| crate::i18n::trf("err.gw.bind", &[("e", &e.to_string())]))?;
        let stop = Arc::new(AtomicBool::new(false));
        let serving = Arc::new(AtomicBool::new(true));
        let server = Arc::new(server);
        {
            let mut g = self.inner.lock().unwrap();
            g.running = true;
            g.port = port;
            g.stop = Some(stop.clone());
            g.server = Some(server.clone());
            g.serving = Some(serving.clone());
        }
        let gw = self.clone();
        let server2 = server.clone();
        let stop2 = stop.clone();
        let serving2 = serving.clone();
        std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match server2.recv_timeout(Duration::from_millis(300)) {
                    Ok(Some(req)) => {
                        let gw = gw.clone();
                        std::thread::spawn(move || {
                            if let Err(e) = handle(req, &gw) {
                                crate::flowlog::log("relay", "req-fail", &e);
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }

            serving2.store(false, Ordering::Relaxed);
        });
        let gw2 = self.clone();
        let p2 = paths;
        std::thread::spawn(move || loop {
            let _ = gw2.warm_quota(&p2, 2, |_| {});
            if !gw2.inner.lock().unwrap().running {
                break;
            }
            std::thread::sleep(Duration::from_millis(QUOTA_TTL_MS));
        });
        crate::flowlog::log("relay", "start", &format!("port={port} upstream={UPSTREAM}"));

        let me = self.clone();
        let stop = self.inner.lock().unwrap().stop.clone();
        let halted = move || stop.as_ref().map_or(false, |s| s.load(Ordering::Relaxed));
        std::thread::spawn(move || loop {
            for _ in 0..(PROBE_EVERY_MS / 500) {
                if halted() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            if halted() {
                return;
            }

            me.probe_tick(&Paths::detect());
        });
        Ok(())
    }

    pub fn stop(&self) {
        let (stop, server, serving, port) = {
            let mut g = self.inner.lock().unwrap();
            let s = g.stop.take();
            let srv = g.server.take();
            let sv = g.serving.take();
            g.running = false;
            (s, srv, sv, g.port)
        };
        let Some(s) = stop else { return };
        s.store(true, Ordering::Relaxed);

        if let Some(srv) = server {
            srv.unblock();
        }
        if let Some(sv) = serving {
            for _ in 0..40 {
                if !sv.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        crate::flowlog::log("relay", "stop", &format!("port={port}"));
    }

    pub fn refresh_quota(&self, paths: &Paths, force: bool) -> Result<usize, String> {
        let mut waited = 0u64;
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                if !g.refreshing {
                    g.refreshing = true;
                    break;
                }
            }
            if waited >= 120_000 {
                return Err(crate::i18n::tr("err.gw.busy_refresh"));
            }
            std::thread::sleep(Duration::from_millis(300));
            waited += 300;
        }

        let accounts: Vec<(String, String)> = store::list_accounts(paths)
            .map(|v| v.into_iter().map(|a| (a.id, a.name)).collect())
            .unwrap_or_default();
        let total = accounts.len();
        let mut n = 0usize;
        let mut failed: Vec<String> = Vec::new();

        for (i, (id, name)) in accounts.iter().enumerate() {
            if !force {
                let g = self.inner.lock().unwrap();
                if let Some((at, _)) = g.quota.get(id) {
                    if now_ms().saturating_sub(*at) < QUOTA_TTL_MS {
                        continue;
                    }
                }
            }
            let mut got = None;
            let mut last = String::new();
            for attempt in 0..4u64 {
                match store::account_quota(paths, id) {
                    Ok(ov) => {
                        got = Some(ov);
                        break;
                    }
                    Err(e) => {
                        last = e;
                        std::thread::sleep(Duration::from_millis(600 + attempt * 700));
                    }
                }
            }
            match got {
                Some(ov) => {
                    self.inner.lock().unwrap().quota.insert(id.clone(), (now_ms(), ov));
                    n += 1;
                }
                None => {
                    let short: String = last.chars().take(140).collect();
                    crate::flowlog::log("relay", "quota-fail", &format!("{name}: {short}"));
                    failed.push(name.clone());
                }
            }
            if i + 1 < total {
                std::thread::sleep(Duration::from_millis(150));
            }
        }

        let snap = {
            let mut g = self.inner.lock().unwrap();
            g.refreshing = false;
            g.last_refresh = Some(store::now_ts());
            g.quota_total = total;
            g.last_failed = failed;
            quota_snapshot(&g)
        };

        write_quota_cache(paths, snap);
        Ok(n)
    }

    fn candidates(&self, paths: &Paths, model: &str) -> Vec<Candidate> {
        let accounts = store::list_accounts(paths).unwrap_or_default();
        let secret = crate::zcrypto::default_secret(&paths.home);
        let (policy, pinned) = {
            let g = self.inner.lock().unwrap();
            (g.policy.clone(), g.pinned.clone())
        };
        let mut known: Vec<Candidate> = vec![];
        let mut unknown: Vec<Candidate> = vec![];
        for acc in &accounts {
            if policy == POLICY_PINNED && pinned.as_deref() != Some(acc.id.as_str()) {
                continue;
            }

            {
                let g = self.inner.lock().unwrap();
                if let Some(t) = g.blocked.get(&acc.id) {
                    if *t > now_ms() {
                        continue;
                    }
                }
            }
            // 有缓存 → 按该模型余量算；**没缓存不等于没额度** —— 标成待刷新、排到最后，
            // 而不是像以前那样直接丢弃。那是历史 7364 次 `502 no-account` 的主因：
            // 新加的号还没 warm、或某轮 warm 失败，号就凭空消失了。
            let mut sized: Option<(Option<String>, f64)> = None;
            let mut has_cache = false;
            {
                let mut g = self.inner.lock().unwrap();
                if let Some((_, ov)) = g.quota.get(&acc.id) {
                    has_cache = true;
                    let mut best: Option<(Option<String>, f64)> = None;
                    for p in &ov.plans {
                        let mut here = 0.0f64;
                        let mut hit = false;
                        for it in &p.items {
                            if model_same(&it.name, model) {
                                let r = it.remaining.unwrap_or(0.0);
                                if r > 0.0 {
                                    hit = true;
                                    here += r;
                                }
                            }
                        }
                        if !hit {
                            continue;
                        }
                        best = match best {
                            None => Some((p.expire.clone(), here)),
                            Some((be, bl)) => {
                                let sooner = matches!((&p.expire, &be), (Some(x), Some(b)) if x < b)
                                    || (p.expire.is_some() && be.is_none());
                                if sooner {
                                    Some((p.expire.clone(), here))
                                } else {
                                    Some((be, bl + here))
                                }
                            }
                        };
                    }
                    sized = best;
                } else if !g.quota_dirty.iter().any(|x| x == &acc.id) {
                    g.quota_dirty.push(acc.id.clone());
                }
            }
            if has_cache && sized.is_none() {
                continue;
            }
            let (expire, left) = sized.unwrap_or((None, -1.0));
            let Ok(full) = store::load_account(paths, &acc.id) else { continue };
            let toks = crate::quota::candidate_tokens(&full.credentials, full.config.as_ref(), &secret);
            // 有「上次真试过能通」的指纹就按它取；没有才照列表顺序取第一个
            let Some(jwt) = toks.get(pick_token_index(&toks, full.plan_token.as_deref())).cloned() else {
                continue;
            };
            let c = Candidate {
                id: acc.id.clone(),
                name: acc.name.clone(),
                token: jwt,
                mid: full.virtual_device_mid.unwrap_or_default(),
                expire,
                left,
            };
            if has_cache {
                known.push(c);
            } else {
                unknown.push(c);
            }
        }
        match policy.as_str() {
            POLICY_MOST_LEFT => known.sort_by(|a, b| {
                b.left.partial_cmp(&a.left).unwrap_or(std::cmp::Ordering::Equal).then(a.name.cmp(&b.name))
            }),
            _ => known.sort_by(|a, b| a.expire.cmp(&b.expire).then(a.name.cmp(&b.name))),
        }
        // 余量未知的号一律排在有号的后面：只在没有可用号时才用它们
        unknown.sort_by(|a, b| a.name.cmp(&b.name));
        known.extend(unknown);
        known
    }

    /// 把该会话上次服务过的号挪到队首。空指纹 = **不加粘性**（看不懂的请求不钉号）。
    ///
    /// 以前是全局一个 `sticky: Option<String>`，每次成功都重新钉住同一个号 —— 于是所有
    /// 并发都从同一个号开始，别的号的余量永远用不上。按会话分桶之后：同一场对话仍然
    /// 留在同一个号上（prompt 缓存局部性不变），新对话则优先领一个**还没被别的会话占用**
    /// 的号 —— 不然两个新项目都会照队首挤到同一个号上，分摊就等于没做。
    fn sticky_order(&self, mut list: Vec<Candidate>, skey: &str) -> Vec<Candidate> {
        if list.is_empty() || skey.is_empty() {
            return list;
        }
        let mut g = self.inner.lock().unwrap();
        if g.policy == POLICY_PINNED {
            return list;
        }
        let now = now_ms();
        g.sticky.retain(|_, (_, t)| now.saturating_sub(*t) < STICKY_TTL_MS);
        if let Some((id, _)) = g.sticky.get(skey) {
            if let Some(i) = list.iter().position(|c| &c.id == id) {
                list.rotate_left(i);
                return list;
            }
        }
        // 新会话（或原来那个号已经不在候选里了）：挑一个别人没占的号
        let used: std::collections::HashSet<String> = list
            .iter()
            .filter(|c| g.sticky.values().any(|(id, _)| id == &c.id))
            .map(|c| c.id.clone())
            .collect();
        let i = pick_for_new_session(&list, &used);
        let id = list[i].id.clone();
        if g.sticky.len() >= STICKY_MAX {
            // 到上限就丢最久没用的那条，这张表不许无界增长
            if let Some(k) = g.sticky.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone()) {
                g.sticky.remove(&k);
            }
        }
        g.sticky.insert(skey.to_string(), (id, now));
        list.rotate_left(i);
        list
    }

    /// 请求成功后把这一发实际用的号记回该会话（顺带续命）。
    fn set_sticky(&self, skey: &str, id: &str) {
        if skey.is_empty() {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        if g.policy != POLICY_PINNED {
            g.sticky.insert(skey.to_string(), (id.to_string(), now_ms()));
        }
    }

}

fn live_account_id(paths: &Paths) -> Option<String> {
    let st = store::get_state(paths).ok()?;
    if !st.live_logged_in {
        return None;
    }
    st.active_account_id
}

fn quota_rows_for(g: &Inner, id: Option<&str>) -> Value {
    let Some(id) = id else { return Value::Null };
    let Some((_, ov)) = g.quota.get(id) else { return Value::Null };
    let mut rows: Vec<Value> = vec![];
    for p in &ov.plans {
        for it in &p.items {
            if it.total.is_none() && it.remaining.is_none() {
                continue;
            }
            rows.push(json!({
                "name": it.name,
                "left": it.remaining,
                "total": it.total,
                "reset": it.reset.clone().or_else(|| it.period_end.clone()),
                "expire": p.expire,
                "plan": p.name,
            }));
        }
    }
    json!({ "account": id, "rows": rows })
}

fn models_seen(quota: &HashMap<String, (u64, crate::quota::QuotaOverview)>) -> Vec<String> {
    let mut set: Vec<String> = vec![];
    for (_, ov) in quota.values() {
        for p in &ov.plans {
            for it in &p.items {
                let n = it.name.trim().to_string();
                if !n.is_empty() && !set.iter().any(|x| model_eq(x, &n)) {
                    set.push(n);
                }
            }
        }
    }
    set.sort();
    set
}

fn peek_model(head: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(head);
    let mut from = 0usize;
    while let Some(rel) = head[from..].find("\"model\"") {
        let i = from + rel + "\"model\"".len();
        let rest = &head[i..];
        let mut it = rest.chars().skip_while(|c| c.is_whitespace());
        if it.next() != Some(':') {
            from = i;
            continue;
        }
        let rest: String = it.collect();
        let rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                let m = r[..end].trim().to_string();
                if !m.is_empty() {
                    return Some(m);
                }
            }
        }
        from = i;
    }
    None
}

fn peek_code(head: &[u8]) -> String {
    let s = String::from_utf8_lossy(head);
    let mut from = 0usize;
    while let Some(rel) = s[from..].find("\"code\"") {
        let i = from + rel + "\"code\"".len();
        let rest = &s[i..];
        let mut it = rest.chars().skip_while(|c| c.is_whitespace());
        if it.next() != Some(':') {
            from = i;
            continue;
        }
        let rest: String = it.collect();
        let rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                let c = r[..end].trim().to_string();
                if !c.is_empty() {
                    return c;
                }
            }
        } else {
            let c: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !c.is_empty() {
                return c;
            }
        }
        from = i;
    }
    String::new()
}

fn model_key(s: &str) -> String {
    let flat: String = s
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' '))
        .collect();
    match flat.strip_prefix("glm") {
        Some(rest) => rest.to_string(),
        None => flat,
    }
}

fn model_same(a: &str, b: &str) -> bool {
    let (x, y) = (model_key(a), model_key(b));
    !x.is_empty() && x == y
}

fn backoff_ms(attempt: usize) -> u64 {
    let shift = attempt.saturating_sub(1).min(5) as u32;
    let capped = 2000u64.saturating_mul(1u64 << shift).min(60_000);
    let jitter = (now_ms() % 41) as i64 - 20; 
    ((capped as i64) * (100 + jitter) / 100).max(50) as u64
}

/// 凭证指纹：sha256 前 16 位。账号文件里只落这个，不落明文。
fn token_sha16(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// 按持久化的「上次试通的凭证指纹」选候选；对不上（凭证换了、指纹过期）就退回第一个，
/// 让下一次对话测试重新去猜 —— 宁可退回原行为，也不要因为一条坏提示把号锁死。
fn pick_token_index(tokens: &[String], hint: Option<&str>) -> usize {
    match hint.filter(|h| !h.is_empty()) {
        Some(h) => tokens.iter().position(|t| token_sha16(t) == h).unwrap_or(0),
        None => 0,
    }
}

/// 凭证被上游接受了、但这一发没出话 —— 按状态码给个准确说法。
/// 关键是别把它写成"凭证失效"：那会让人去重新登录，而真正的原因往往是并发超限或上游抖动。
fn probe_gap_label(status: u16) -> String {
    match status {
        200 => "上游认这个凭证，但应答里没有模型内容".to_string(),
        402 => "额度/套餐不足（402）—— 等重置或换号".to_string(),
        429 => "并发或限流（429）—— 这个号此刻被占满（例：正在官方客户端里用）".to_string(),
        s if s >= 500 => format!("上游故障（HTTP {s}）—— 与凭证无关"),
        s => format!("上游认这个凭证，但回了 HTTP {s}"),
    }
}

/// 号级失败的冷却时长。**生产换号和对话测试共用**这一处判断 —— 两边各写一遍迟早会飘，
/// 而测试里那句「真跑会被冷却多久」报错了就等于在骗人。
fn account_cooldown(status: u16) -> u64 {
    if status == 429 { RATE_TTL_MS } else { AUTH_COOLDOWN_MS }
}

/// 非 2xx 且**不是号的问题**时，这条应答怎么定性：`(给人看的标签, 熔断多久)`，0 = 不熔断。
///
/// 优先级：先查明确列出的通道级状态码（路由被关、方法不许、501/505 这种"这条路本身不通"），
/// 再兜 5xx（上游自己挂了，多半是暂时的，短熔断），再兜"没列进来但拿回一页 HTML"
/// —— 实测的 405 拦页就是这一类形状。
/// 剩下的 4xx 多半是这一发请求本身不对：**不熔断**，免得一个客户端的坏请求把整池锁 60 秒。
/// 四种都不换号 —— 与号无关时换下一个只是把同一堵墙再撞一遍。
fn upstream_verdict(status: u16, snip: &str) -> (&'static str, u64) {
    if PATH_STATUS.contains(&status) {
        ("通道被拦（与号无关，换号无意义）", EDGE_COOLDOWN_MS)
    } else if status >= 500 {
        ("上游故障", UPSTREAM_COOLDOWN_MS)
    } else if snip.starts_with('<') {
        ("通道被拦（HTML 拦截页，换号无意义）", EDGE_COOLDOWN_MS)
    } else if status >= 400 {
        ("未预期 4xx", 0u64)
    } else {
        ("未预期应答（既非 2xx 也非 4xx/5xx）", 0u64)
    }
}

/// 把一次请求花掉的 token **就地扣进**额度缓存余量。
///
/// 缓存原本 5 分钟才刷一次：长流把一个号吃干之后，池子还会继续以为它有余量，
/// 于是「用完不主动切」。这里先本地扣，下一发请求就看得见。
///
/// ⚠ 只当**怀疑**用：扣到 0 时调用方去触发一次真实刷新确认，绝不凭估算就把号踢出池。
/// 所以宁少勿多 —— 缓存命中的 `cache_read_input_tokens` 故意不计（多扣会把还有余量的
/// 号误判成空，那正是我们要修的毛病）。
/// 返回是否因此把某一档扣到了 0。
fn drain_cached(ov: &mut crate::quota::QuotaOverview, model: &str, spent: u64) -> bool {
    if spent == 0 {
        return false;
    }
    let t = spent as f64;
    let mut zeroed = false;
    {
        let mut one = |it: &mut crate::quota::QuotaItem| {
            if !model_same(&it.name, model) {
                return;
            }
            let Some(r) = it.remaining else { return };
            let left = (r - t).max(0.0);
            if left <= 0.0 {
                zeroed = true;
            }
            it.used = Some(it.used.unwrap_or(0.0) + (r - left));
            it.remaining = Some(left);
            if let Some(tt) = it.total.filter(|tt| *tt > 0.0) {
                it.percent_used = Some(((tt - left) / tt) * 100.0);
            }
        };
        for it in ov.items.iter_mut() {
            one(it);
        }
        for p in ov.plans.iter_mut() {
            for it in p.items.iter_mut() {
                one(it);
            }
        }
    }
    zeroed
}

/// 会话指纹：API Key + `system` + 第一条 `messages` 里的全部文本，SHA-256 前 16 字节。
///
/// 同一场对话继续钉同一个号（prompt 缓存局部性不受影响），不同对话、不同客户端
/// 自然分摊到不同号 —— 这就是「同时只能用一个号的额度」的解法。
/// 解析不出来就返回空串，空串表示**不加粘性**：宁可换号，也不把看不懂的请求钉死。
///
/// 已知边界：`system` 写成字符串与写成块数组的指纹不同（块里的 `"type":"text"` 也是文本）。
/// 只要同一场对话的写法稳定就没问题，写法变了不过是重新钉一次号，不影响正确性。
fn session_key(body: &[u8], key_tag: &str) -> String {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let mut h = Sha256::new();
    h.update(b"zpool-sess|");
    h.update(key_tag.as_bytes());
    h.update([0u8]);
    let mut saw = false;
    if let Some(s) = v.get("system") {
        saw |= push_strings(s, &mut h, 0);
        h.update([1u8]);
    }
    if let Some(m) = v.get("messages").and_then(Value::as_array).and_then(|a| a.first()) {
        saw |= push_strings(m, &mut h, 0);
    }
    // 一个文本都没抓到（比如空 messages）就别钉号 —— 否则这类请求会全落在同一个常量指纹上
    if !saw {
        return String::new();
    }
    let digest = h.finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// 按文档顺序收集字符串叶子喂进哈希，返回「有没有抓到文本」。
/// 键名不参与，这样同一份内容换个键序不会变指纹（`serde_json::Map` 默认按键排序，本就确定性）。
fn push_strings(v: &Value, h: &mut Sha256, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    match v {
        Value::String(s) => {
            h.update(s.as_bytes());
            h.update([0u8]);
            !s.trim().is_empty()
        }
        Value::Array(a) => a.iter().fold(false, |acc, x| push_strings(x, h, depth + 1) || acc),
        Value::Object(o) => o.values().fold(false, |acc, x| push_strings(x, h, depth + 1) || acc),
        _ => false,
    }
}

fn account_session(id: &str, seed: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"zpool-sid|");
    h.update(id.as_bytes());
    h.update(b"|");
    h.update(seed.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b).to_string()
}

fn day_seed() -> String {
    (now_ms() / 86_400_000).to_string()
}

fn model_eq(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim().to_ascii_lowercase().replace(['-', '_', ' '], "");
    let (x, y) = (n(a), n(b));
    !x.is_empty() && !y.is_empty() && (x == y || x.contains(&y) || y.contains(&x))
}

fn body_model(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("model").and_then(|m| m.as_str()).map(|s| s.to_string())
}

struct Meter<R> {
    inner: std::sync::Arc<Mutex<Inner>>,
    src: R,
    tail: Vec<u8>,

    head: Vec<u8>,
    tokens: u64,
    tokens_in: u64,

    cache: u64,

    bytes: u64,

    started: u64,

    first_at: Option<u64>,

    /// 本地扣减额度要落在这个号上（`rec.acct` 是显示名，不够唯一）
    acct_id: String,

    /// 实际发给上游的模型名 —— 扣额度按它匹配，不是按调用方要的那个
    up_model: String,

    rec: Option<crate::usage::UsageRecord>,
    path: std::path::PathBuf,
}

impl<R: Read> Read for Meter<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.src.read(out)?;
        let now = now_ms();
        if n == 0 {

            if let Some(t) = scan_u64_key(&self.tail, b"input_tokens") {
                self.tokens_in = self.tokens_in.max(t);
            }
            if let Some(t) = scan_u64_after(&self.tail, b"output_tokens") {
                self.tokens = self.tokens.max(t);
            }
            if let Some(t) = scan_u64_key(&self.tail, b"cache_read_input_tokens") {
                self.cache = self.cache.max(t);
            }
            let ms = now.saturating_sub(self.started);
            let ttfb = self.first_at.map(|f| f.saturating_sub(self.started));
            let mut code = peek_code(&self.head);
            if code.is_empty() {
                code = peek_code(&self.tail);
            }
            // 只有真正成功的一发才扣减 —— 失败或半途断掉的流不能算进额度
            let served = self.rec.as_ref().is_some_and(|r| r.status == 200);
            if let Some(mut rec) = self.rec.take() {
                rec.tokens_in = self.tokens_in;
                rec.tokens_out = self.tokens;
                rec.cache = self.cache;
                rec.ttfb = ttfb;
                rec.ms = ms;
                rec.bytes = self.bytes;
                rec.code = code;
                crate::usage::append(&self.path, &rec);
            }
            let mut g = self.inner.lock().unwrap();
            if served {
                // A1：把这一发花掉的 token 就地扣进额度缓存余量。以前缓存 5 分钟才刷一次，
                // 长流把号吃干之后池子还在以为它有余量 —— 这就是「用完不主动切」的根因。
                // 扣到 0 只当**怀疑**：塞进待确认队列，由真实刷新定案，绝不凭估算把号踢掉。
                let spent = self.tokens_in.saturating_add(self.tokens);
                if spent > 0 {
                    if let Some((_, ov)) = g.quota.get_mut(&self.acct_id) {
                        if drain_cached(ov, &self.up_model, spent)
                            && !g.quota_dirty.iter().any(|x| x == &self.acct_id)
                        {
                            g.quota_dirty.push(self.acct_id.clone());
                        }
                    }
                }
            }
            g.last_total_ms = Some(ms);

            g.tokens_sum = g.tokens_sum.saturating_add(self.tokens);
            let gen_ms = ms.saturating_sub(ttfb.unwrap_or(0));
            if self.tokens > 0 && gen_ms > 0 {
                g.last_gen_tps = Some(self.tokens as f64 * 1000.0 / gen_ms as f64);
            }
            return Ok(0);
        }

        if self.first_at.is_none() {
            self.first_at = Some(now);
            let mut g = self.inner.lock().unwrap();
            g.last_ttfb_ms = Some(now.saturating_sub(self.started));
            g.last_total_ms = None;
        }
        self.bytes += n as u64;
        if self.head.len() < 2048 {
            let room = 2048 - self.head.len();
            self.head.extend_from_slice(&out[..n.min(room)]);
        }

        self.tail.extend_from_slice(&out[..n]);
        if self.tail.len() > 8192 {
            let cut = self.tail.len() - 8192;
            self.tail.drain(..cut);
        }
        if let Some(t) = scan_u64_after(&self.tail, b"output_tokens") {
            self.tokens = self.tokens.max(t);
        }
        if let Some(t) = scan_u64_key(&self.tail, b"input_tokens") {
            self.tokens_in = self.tokens_in.max(t);
        }
        if let Some(t) = scan_u64_key(&self.tail, b"cache_read_input_tokens") {
            self.cache = self.cache.max(t);
        }
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        g.bytes_out += n as u64;

        let (bytes, tokens) = (g.bytes_out, g.tokens_sum);
        g.meter.push((now, bytes, tokens));
        Ok(n)
    }
}

fn port_answers(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

fn lan_host() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "<本机IP>".into())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn scan_u64_after(hay: &[u8], needle: &[u8]) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut i = 0usize;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            while j < hay.len() && !hay[j].is_ascii_digit() && j < i + needle.len() + 16 {
                j += 1;
            }
            let mut v: u64 = 0;
            let mut any = false;
            while j < hay.len() && hay[j].is_ascii_digit() {
                v = v.saturating_mul(10).saturating_add((hay[j] - b'0') as u64);
                any = true;
                j += 1;
            }
            if any {
                best = Some(best.map_or(v, |b: u64| b.max(v)));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    best
}

fn scan_u64_key(hay: &[u8], needle: &[u8]) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut i = 0usize;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            let bounded = i == 0 || !(hay[i - 1].is_ascii_alphanumeric() || hay[i - 1] == b'_');
            if bounded {
                let mut j = i + needle.len();
                let lim = (i + needle.len() + 16).min(hay.len());
                while j < lim && !hay[j].is_ascii_digit() {
                    j += 1;
                }
                let mut v: u64 = 0;
                let mut any = false;
                while j < hay.len() && hay[j].is_ascii_digit() {
                    v = v.saturating_mul(10).saturating_add((hay[j] - b'0') as u64);
                    any = true;
                    j += 1;
                }
                if any {
                    best = Some(best.map_or(v, |b: u64| b.max(v)));
                }
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    best
}

fn meter_delta(g: &Inner) -> (f64, u64, u64) {
    let (Some(first), Some(last)) = (g.meter.first(), g.meter.last()) else {
        return (0.0, 0, 0);
    };
    if last.0 <= first.0 {
        return (0.0, 0, 0);
    }
    (
        (last.0 - first.0) as f64 / 1000.0,
        last.1.saturating_sub(first.1),
        last.2.saturating_sub(first.2),
    )
}

#[derive(Clone, Default)]
struct Health {
    ok: u64,
    fail: u64,

    streak: u32,
    last_ms: Option<u64>,
    last_at: Option<u64>,
    last_err: String,

    history: Vec<(u64, Option<u64>)>,
}

impl Health {
    fn json(&self) -> Value {
        let ok_recent = self.history.iter().filter(|(_, m)| m.is_some()).count();
        json!({
            "ok": self.ok,
            "fail": self.fail,
            "streak": self.streak,
            "lastMs": self.last_ms,
            "lastAt": self.last_at,
            "lastErr": self.last_err,
            "rate": if self.history.is_empty() { Value::Null }
                    else { json!((ok_recent as f64 / self.history.len() as f64 * 100.0).round()) },
            "history": self.history.iter().map(|(t, m)| json!({ "at": t, "ms": m })).collect::<Vec<_>>(),
        })
    }
}

fn auth_token(req: &tiny_http::Request) -> String {
    for h in req.headers() {
        match h.field.as_str().as_str().to_ascii_lowercase().as_str() {
            "x-api-key" => return h.value.as_str().to_string(),
            "authorization" => {
                let v = h.value.as_str();
                return v.strip_prefix("Bearer ").unwrap_or(v).trim().to_string();
            }
            _ => {}
        }
    }
    String::new()
}

fn mint_stats(g: &Inner) -> Value {
    let now = now_ms();
    let recent = g.mint_times.iter().filter(|t| now.saturating_sub(**t) < 600_000).count();
    json!({
        "pool": g.params.len(),
        "waiters": g.waiters,
        "active": now.saturating_sub(g.last_use) < ACTIVE_WINDOW_MS,
        "mints": g.mints,
        "mints10min": recent,
    })
}

fn norm_path(url: &str) -> String {
    let p = url.split('?').next().unwrap_or(url);
    let mut s = p.to_string();
    while let Some(rest) = s.strip_prefix("/v1/v1") {
        s = rest.to_string();
    }
    if s.starts_with("/messages") || s.starts_with("/count_tokens") {
        s = format!("/v1{s}");
    }
    s
}

/// 只保证单调、不保证精确：数 `system` / `messages` / `tools` 下的字符串叶子。
/// CJK 全角按 1 字≈1 token、其余按 4 字符≈1 token —— 纯按 4 折算会把中文低估约 4 倍，
/// 客户端据此预算就会塞过头。
fn estimate_input_tokens(raw: &[u8]) -> u64 {
    fn is_wide(c: char) -> bool {
        let u = c as u32;
        (0x3000..=0x30ff).contains(&u)
            || (0x3400..=0x4dbf).contains(&u)
            || (0x4e00..=0x9fff).contains(&u)
            || (0xac00..=0xd7af).contains(&u)
            || (0xf900..=0xfaff).contains(&u)
            || (0xff00..=0xffef).contains(&u)
    }
    fn walk(v: &Value, wide: &mut u64, ascii: &mut u64) {
        match v {
            Value::String(s) => {
                for c in s.chars() {
                    if is_wide(c) {
                        *wide += 1;
                    } else {
                        *ascii += 1;
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, wide, ascii)),
            Value::Object(o) => o.values().for_each(|x| walk(x, wide, ascii)),
            _ => {}
        }
    }
    let (mut wide, mut ascii) = (0u64, 0u64);
    if let Ok(v) = serde_json::from_slice::<Value>(raw) {
        for k in ["system", "messages", "tools"] {
            if let Some(x) = v.get(k) {
                walk(x, &mut wide, &mut ascii);
            }
        }
    }
    if wide + ascii == 0 {
        return (raw.len() as u64 / 4).max(1);
    }
    (wide + ascii.div_ceil(4)).max(1)
}

fn web_dirs() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(d) = std::env::var("ZPOOL_WEB_DIR") {
        if !d.trim().is_empty() {
            v.push(std::path::PathBuf::from(d));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("web"));
        }
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    if src.is_dir() {
        v.push(src);
    }
    v
}

fn page(name: &str, embedded: &str) -> String {
    for dir in web_dirs() {
        let p = dir.join(name);
        if let Ok(s) = std::fs::read_to_string(&p) {
            crate::flowlog::log("relay", "page-disk", &p.display().to_string());
            return s;
        }
    }
    embedded.to_string()
}

fn reply_html(req: tiny_http::Request, body: String) -> Result<(), String> {
    let mk = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(200),
        vec![
            mk("Content-Type", "text/html; charset=utf-8"),
            mk("Cache-Control", "no-store, must-revalidate"),
        ],
        std::io::Cursor::new(body.into_bytes()),
        None,
        None,
    ));
    Ok(())
}

fn reply_json(req: tiny_http::Request, code: u16, v: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    let h = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(code),
        vec![h],
        std::io::Cursor::new(body),
        None,
        None,
    ));
    Ok(())
}

fn reply_text(req: tiny_http::Request, body: String, filename: &str) -> Result<(), String> {
    let mk = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(200),
        vec![
            mk("Content-Type", "text/plain; charset=utf-8"),
            mk("Content-Disposition", &format!("attachment; filename=\"{filename}\"")),
            mk("Cache-Control", "no-store"),
        ],
        std::io::Cursor::new(body.into_bytes()),
        None,
        None,
    ));
    Ok(())
}

const SECRET_KEYS: [&str; 12] = [
    "password",
    "refresh_token",
    "refreshtoken",
    "access_token",
    "accesstoken",
    "id_token",
    "jwt",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "token",
];

fn is_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|m| k == *m || k.ends_with(&format!("_{m}")))
}

fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n == 0 {
        return String::new();
    }
    if n <= 4 {
        return "***".to_string();
    }
    let head: String = s.chars().take(4).collect();
    format!("{head}***")
}

fn mask_json(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_secret_key(k) {
                    if let Some(s) = val.as_str() {
                        *val = json!(mask_secret(s));
                    }
                } else {
                    mask_json(val);
                }
            }
        }
        Value::Array(arr) => {
            for x in arr.iter_mut() {
                mask_json(x);
            }
        }
        _ => {}
    }
}

fn reply_json_masked(req: tiny_http::Request, code: u16, v: &Value, from_loopback: bool) -> Result<(), String> {
    if from_loopback {
        return reply_json(req, code, v);
    }
    let mut c = v.clone();
    mask_json(&mut c);
    reply_json(req, code, &c)
}

fn system_blocks(paths: &Paths) -> Result<Vec<Value>, String> {
    // 按抽取来源缓存：设置里换了 ZCode 路径就得重抽，否则整个进程寿命内都用旧的两块。
    static B: std::sync::Mutex<Option<(String, Vec<Value>)>> = std::sync::Mutex::new(None);
    let key = crate::prompt::cache_key(paths);
    let lock = B.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((k, v)) = lock.as_ref() {
        if *k == key {
            return Ok(v.clone());
        }
    }
    drop(lock);
    let v = crate::prompt::system_blocks(paths)?;
    *B.lock().unwrap_or_else(|p| p.into_inner()) = Some((key, v.clone()));
    Ok(v)
}

fn external_body(
    raw: &[u8],
    mid: &str,
    model: &str,
    session: &str,
    paths: &Paths,
) -> Result<Vec<u8>, (u16, String)> {
    let mut v: Value = serde_json::from_slice(raw)
        .map_err(|e| (400, format!("请求体必须是 UTF-8 编码的 JSON：{e}")))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| (400, "请求体必须是 JSON 对象".to_string()))?;
    obj.insert("model".into(), json!(model));
    obj.entry("max_tokens").or_insert(json!(8192));

    let caller = obj.get("system").cloned();
    let mut blocks = system_blocks(paths).map_err(|e| (503, e))?;
    match caller {
        Some(Value::String(s)) if !s.trim().is_empty() => {
            if !crate::prompt::is_canonical_identity(&s) {
                blocks.push(json!({ "type": "text", "text": s }))
            }
        }
        // 上游硬上限是 system **最多 3 块**（实测：4 块必 405/3012，与体量和内容都无关）。
        // 我们固定占 2 块，所以调用方的多块 system 必须并成 1 块 —— 只拼接，原文不动，
        // 客户端自己的提示词与工具链因此完整保留。
        Some(Value::Array(a)) => {
            let mut parts: Vec<String> = Vec::new();
            let mut wants_cache = false;
            for b in a {
                if let Some(t) = b.get("text").and_then(Value::as_str) {
                    if t.trim().is_empty() || crate::prompt::is_canonical_identity(t) {
                        continue;
                    }
                    if b.get("cache_control")
                        .and_then(|c| c.get("type"))
                        .and_then(Value::as_str)
                        == Some("ephemeral")
                    {
                        wants_cache = true;
                    }
                    parts.push(t.to_string());
                }
            }
            if !parts.is_empty() {
                let merged = parts.join("\n\n");
                blocks.push(if wants_cache {
                    json!({ "type": "text", "text": merged, "cache_control": { "type": "ephemeral" } })
                } else {
                    json!({ "type": "text", "text": merged })
                });
            }
        }
        _ => {}
    }
    obj.insert("system".into(), Value::Array(blocks));

    let uid = json!({
        "device_id": mid,
        "account_uuid": "",
        "session_id": session,
    })
    .to_string();
    obj.insert("metadata".into(), json!({ "user_id": uid }));
    serde_json::to_vec(&v).map_err(|e| (500, e.to_string()))
}

/// 选号：按 policy 排好、再把本会话上次用的号挪到队首；该模型全库无额度时回退到另一个模型。
/// 刷完额度要能原样重跑一遍，所以把这段从 `handle_external` 里摘出来。
/// 上游错误体里的业务码 → 人话。只点名线上真见过的几个。
fn upstream_reason(code: i64) -> Option<&'static str> {
    match code {
        3009 => Some("并发超限 —— 同一个号的模型并发被占满（例：这个号正在官方客户端里用）"),
        3012 => Some("提示词被判异常 —— 身份段重复或被改动"),
        _ => None,
    }
}

/// 从应答里取业务码（`{"code":3009}`）并翻成人话；取不到就回 None。
fn upstream_why(snip: &str) -> Option<String> {
    let code = peek_code(snip.as_bytes());
    match code.parse::<i64>() {
        Ok(c) if c != 0 => Some(match upstream_reason(c) {
            Some(t) => format!("{t}（code {c}）"),
            None => format!("上游业务码 {c}"),
        }),
        _ => None,
    }
}

/// 200 却没有正文时，进一步说清应答是什么形状 —— 两者的处置不一样。
/// 必须喂**完整** body：`body_snippet` 截到 120 字会把 JSON 截断，解析必然失败。
fn reply_shape(s: &str) -> Option<&'static str> {
    let v = serde_json::from_str::<Value>(s).ok()?;
    let arr = v.get("content").and_then(Value::as_array)?;
    // 有正文就别报形状问题（正常路径走不到这儿，但函数得自己站得住）
    if arr
        .iter()
        .any(|b| b.get("text").and_then(Value::as_str).is_some_and(|t| !t.trim().is_empty()))
    {
        return None;
    }
    if arr.iter().any(|b| b.get("thinking").is_some()) {
        return Some("只有思考块、没有正文 —— max_tokens 太小或模型正在思考");
    }
    Some("有 content 数组但里面没有正文")
}

/// 这份凭证是不是**认证失败**（该换下一份试试）。
/// 只有 401/403 才是「凭证不对」；200/402/429/5xx 都说明上游认了这个凭证，
/// 只是这一刻出不了话 —— 把它们混为一谈就会把对的凭证判成坏的。
fn is_auth_rejected(status: u16) -> bool {
    matches!(status, 401 | 403)
}

/// 从应答里捞出模型说的话。优先非流式 JSON 的 `content[].text`；
/// 拿回的是 SSE 或半截 JSON 就退而求其次扫第一段 `"text":"…"`。
/// 返回 `None` 表示「没收到回复」—— 这正是对话测试要告诉用户的事。
fn extract_reply_text(s: &str) -> Option<String> {
    const CAP: usize = 160;
    if let Ok(v) = serde_json::from_str::<Value>(s) {
        if let Some(t) = v
            .get("content")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find_map(|b| b.get("text").and_then(Value::as_str)))
        {
            if !t.trim().is_empty() {
                return Some(t.chars().take(CAP).collect());
            }
        }
    }
    let i = s.find("\"text\"")?;
    let rest = &s[i + "\"text\"".len()..];
    let j = rest.find(':')?;
    let mut it = rest[j + 1..].chars().skip_while(|c| c.is_whitespace());
    if it.next() != Some('"') {
        return None;
    }
    let mut out = String::new();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
            continue;
        }
        if c == '"' {
            break;
        }
        out.push(c);
        if out.chars().count() >= CAP {
            break;
        }
    }
    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 对话测试试哪一档：额度缓存里有余额的先试，都没余额或没缓存就用对外默认档。
fn test_model(gw: &Gateway, id: &str) -> String {
    let g = gw.inner.lock().unwrap();
    if let Some((_, ov)) = g.quota.get(id) {
        for m in EXTERNAL_MODELS {
            if ov.plans
                .iter()
                .flat_map(|p| p.items.iter())
                .any(|it| model_same(&it.name, m) && it.remaining.unwrap_or(0.0) > 0.0)
            {
                return m.to_string();
            }
        }
    }
    EXTERNAL_MODELS[0].to_string()
}

/// 「对话测试」：向指定号真发一发最小 messages，看能不能拿到回复。
///
/// 走的是和生产**完全一样**的出站路径（`external_body` 改写 + `set_relay_headers` +
/// `relay_agent`）—— 少一样，测出来的结论就不代表真实请求。
///
/// ⚠ 这会**真烧掉一点点额度**（一发 hi、max_tokens 给得很小），所以按钮旁边写明白。
/// ⚠ 只读：不冷却这个号、也不熔断通道。手点一下失败就把号池冻住是帮倒忙；
/// 失败原因直接借 `upstream_verdict` 报出来，附上「真跑的话会被冷却多久」。
fn chat_test(gw: &Gateway, paths: &Paths, id: &str) -> Value {
    let name = store::list_accounts(paths)
        .unwrap_or_default()
        .into_iter()
        .find(|a| a.id == id)
        .map(|a| a.name)
        .unwrap_or_else(|| id.to_string());
    let fail = |j: Value| -> Value {
        let mut o = j.as_object().cloned().unwrap_or_default();
        o.insert("ok".to_string(), json!(false));
        o.insert("name".to_string(), json!(name));
        Value::Object(o)
    };

    let acc = match store::load_account(paths, id) {
        Ok(a) => a,
        Err(e) => return fail(json!({ "error": format!("读不到这个号：{e}") })),
    };
    let secret = crate::zcrypto::default_secret(&paths.home);
    let toks = crate::quota::candidate_tokens(&acc.credentials, acc.config.as_ref(), &secret);
    if toks.is_empty() {
        return fail(json!({ "error": "这个号没有可用凭证 —— 先重新登录一次" }));
    }
    let mid = acc.virtual_device_mid.clone().unwrap_or_default();
    let model = test_model(gw, id);
    let sess = account_session(id, &day_seed());
    let plain = json!({
        "model": model,
        // 64 已经够短（一发 hi），但不能再小了：这类模型会先吐 thinking 块，
        // 16 个 token 全花在思考上就会「HTTP 200 却没有 text 块」，看着像没回复。
        "max_tokens": 64,
        "messages": [{ "role": "user", "content": "hi" }],
    })
    .to_string();
    let out_body = match external_body(plain.as_bytes(), &mid, &model, &sess, paths) {
        Ok(b) => b,
        Err((_, e)) => return fail(json!({ "model": model, "error": format!("组装请求失败：{e}") })),
    };

    // 依次试这个号的候选凭证，**谁真的能用就记住谁**。
    // 候选顺序本身靠不住：`candidate_tokens` 把 provider 的 coding-plan apiKey 排最前，
    // 而这条端点不认那种 key —— 实测三个带 apiKey 的号一律 401（空 body），
    // 唯一没有 apiKey、只能用 zcodejwttoken 的号正常 200。
    // 上限 4 个：每一发都是真请求，再多就是在烧额度、撞网关。
    let start = pick_token_index(&toks, acc.plan_token.as_deref());
    let order: Vec<usize> = (0..toks.len()).map(|k| (start + k) % toks.len()).take(MAX_PROBE_TOKENS).collect();
    let proxy = gw.inner.lock().unwrap().relay_proxy.clone();
    let agent = relay_agent(proxy.as_deref(), 45);
    let target = format!("{UPSTREAM}/v1/messages");
    let mut tried: Vec<Value> = vec![];
    let mut out: Value = json!({ "ok": false, "error": "没试出结果" });

    let remember = |sha: &str| -> bool {
        // 只存 sha256 前 16 位，账号文件里不落明文凭证
        let mut saved = acc.clone();
        saved.plan_token = Some(sha.to_string());
        store::save_account(paths, &saved).is_ok()
    };
    let cred = |i: usize, sha: &str, persisted: bool, was: bool| json!({
        "index": i + 1, "total": toks.len(), "sha8": sha[..8].to_string(),
        "persisted": persisted, "wasRemembered": was,
    });
    let mut settled = false;

    for i in order {
        let sha = token_sha16(&toks[i]);
        let t0 = now_ms();
        let sent = set_relay_headers(agent.request("POST", &target), &toks[i]).send_bytes(&out_body);
        let ms = now_ms().saturating_sub(t0);
        let (status, reply, snip, net, shape) = match sent {
            Ok(r) => {
                let st = r.status();
                let mut buf = String::new();
                let _ = r.into_reader().take(8192).read_to_string(&mut buf);
                let reply = extract_reply_text(&buf);
                let shape = if reply.is_none() { reply_shape(&buf) } else { None };
                (Some(st), reply, crate::quota::body_snippet(&buf), None, shape)
            }
            Err(ureq::Error::Status(code, r)) => {
                let mut buf = String::new();
                let _ = r.into_reader().take(600).read_to_string(&mut buf);
                (Some(code), None, crate::quota::body_snippet(&buf), None, None)
            }
            Err(e) => (None, None, String::new(), Some(e.to_string()), None),
        };
        let why = if snip.is_empty() { None } else { upstream_why(&snip).or_else(|| shape.map(String::from)) };
        let verdict = match (&status, &reply) {
            (_, Some(_)) => "出话了",
            (Some(st), None) if !is_auth_rejected(*st) => "凭证可用，但这一刻没出话",
            (Some(401), None) => "凭证失效 —— 这个号要重新登录",
            (Some(403), None) => "有身份但没权限",
            (Some(_), None) => "未预期应答",
            (None, _) => "网络错误",
        };
        // 每一发都单独留下状态与应答片段。以前只保留最后一条，结果 #1 拿到的 200
        // 被 #3 的 401 覆盖，界面就成了「无回复 HTTP 401 · 试过3份」，真因（并发超限）全丢了。
        tried.push(json!({
            "index": i + 1, "sha8": sha[..8].to_string(), "status": status, "ms": ms,
            "verdict": verdict, "why": why.clone(), "snippet": snip.clone(),
        }));

        if let Some(t) = reply {
            let persisted = remember(&sha);
            out = json!({ "ok": true, "authOk": true, "status": status, "ms": ms, "reply": t,
                          "credential": cred(i, &sha, persisted, acc.plan_token.as_deref() == Some(sha.as_str())) });
            settled = true;
            break;
        }
        // 上游只要认了这个凭证（不是 401/403），就到此为止：再往下试多半会撞上那条端点根本不认的
        // provider apiKey，反而把「凭证其实是对的」盖成 401。出不了话是另一回事，照实报。
        if let Some(st) = status {
            if !is_auth_rejected(st) {
                let persisted = remember(&sha);
                out = json!({
                    "ok": false, "authOk": true, "status": st, "ms": ms,
                    "kind": why.or_else(|| shape.map(String::from)).unwrap_or_else(|| probe_gap_label(st)),
                    "snippet": snip, "credential": cred(i, &sha, persisted, false),
                });
                settled = true;
                break;
            }
        }
        out = json!({ "ok": false, "authOk": false, "status": status, "ms": ms,
                      "kind": verdict, "error": net, "snippet": snip });
    }

    // 一份凭证都没被接受过：清掉提示，别把一次失败的猜测固化成长期行为
    if !settled && acc.plan_token.is_some() {
        let mut cleared = acc.clone();
        cleared.plan_token = None;
        let _ = store::save_account(paths, &cleared);
        tried.push(json!({ "note": "所有凭证都被拒，已清掉记住的那一份" }));
    }
    if let Some(o) = out.as_object_mut() {
        o.insert("name".to_string(), json!(name));
        o.insert("model".to_string(), json!(model));
        o.insert("attempted".to_string(), json!(tried));
        o.insert("candidates".to_string(), json!(toks.len()));
    }
    crate::flowlog::log("relay", "chat-test", &format!("{}", out));
    out
}

fn pick_accounts(gw: &Gateway, paths: &Paths, model: &mut String, skey: &str, mmode: &str) -> Vec<Candidate> {
    let mut list = gw.sticky_order(gw.candidates(paths, model), skey);
    if list.is_empty() && mmode == MODEL_AUTO {
        for alt in EXTERNAL_MODELS.iter().filter(|m| **m != model.as_str()) {
            let c2 = gw.sticky_order(gw.candidates(paths, alt), skey);
            if !c2.is_empty() {
                crate::flowlog::log("relay", "model-fallback", &format!("{model} 全库无额度 → 回退到 {alt}"));
                *model = alt.to_string();
                list = c2;
                break;
            }
        }
    }
    list
}

/// 新会话该钉哪个号：按 policy 排好的顺序找第一个**还没被别的会话占用**的号；
/// 全被占用就回到队首 —— 此时共用一个号好过把请求判成「池子里没人」。
fn pick_for_new_session(list: &[Candidate], used: &std::collections::HashSet<String>) -> usize {
    list.iter().position(|c| !used.contains(&c.id)).unwrap_or(0)
}

fn handle_external(
    req: tiny_http::Request,
    gw: &Gateway,
    paths: &Paths,
    path: &str,
    body: &[u8],
    key_tag: &str,
) -> Result<(), String> {
    let mut slot = Some(req);
    if !gw.inner.lock().unwrap().external {
        return reply_json(
            slot.take().unwrap(),
            403,
            &json!({ "type": "error",
                     "error": { "type": "permission_error",
                                "message": "对外接口没开 —— 到工具的「反代」页打开它" } }),
        );
    }

    // 熔断期：一个请求都不往上游发。撞得越勤，边缘拦得越久（实测 405 三分钟内累计 2870 发）。
    let waiting = { gw.inner.lock().unwrap().edge.waiting(now_ms()) };
    if let Some((edge_left, edge_first)) = waiting {
        let secs = edge_left.div_euclid(1000).max(1);
        if edge_first {
            crate::flowlog::log("relay", "edge-wait", &format!("上游通道在熔断中，还剩 {secs}s —— 期间进来的请求直接挡回，不出站"));
        }
        return reply_json(
            slot.take().unwrap(),
            503,
            &json!({ "type": "error",
                     "error": { "type": "overloaded_error",
                                "message": format!("上游这条通道正被边缘拦截（HTTP 405），已熔断冷却，约 {secs}s 后重新放行；期间不再出站") } }),
        );
    }

    let mut model = body_model(body).unwrap_or_else(|| EXTERNAL_MODELS[0].to_string());

    let client_model = model.clone();
    let (mmode, mpin) = {
        let g = gw.inner.lock().unwrap();
        (g.model_mode.clone(), g.model_pinned.clone())
    };

    if mmode == MODEL_PINNED {
        if let Some(p) = mpin.clone().filter(|x| !x.trim().is_empty()) {
            if p != model {
                crate::flowlog::log("relay", "model-pinned", &format!("请求={model} 指定={p}"));
            }
            model = p;
        }
    }

    let mapped = gw.inner.lock().unwrap().model_map.get(&model).cloned();
    if let Some(to) = mapped.clone() {
        crate::flowlog::log("relay", "model-map", &format!("请求={model} 上游={to}"));
        model = to;
    }

    let usage_path = crate::usage::path_for(&paths.store_dir());

    let mk = |acct: &str, status: u16, code: &str, tries: usize, stream: bool, t: u64| {
        crate::usage::UsageRecord {
            t,
            acct: acct.to_string(),
            model: client_model.clone(),
            up: None,
            tokens_in: 0,
            tokens_out: 0,
            cache: 0,
            ttfb: None,
            ms: 0,
            bytes: 0,
            status,
            code: code.to_string(),
            tries,
            stream,
            mapped: mapped.clone(),
            key: key_tag.to_string(),
        }
    };
    let target = format!("{UPSTREAM}{path}");
    let proxy_url = gw.inner.lock().unwrap().relay_proxy.clone();
    let agent = relay_agent(proxy_url.as_deref(), 600);

    // 会话指纹：同一场对话钉同一个号，不同对话/不同 Key 分摊到不同号。
    let skey = session_key(body, key_tag);
    // 上一轮攒下的「额度待确认」（扣到 0 / 被拒 / 没缓存）在这里排空，后台刷，不挡这一发。
    gw.drain_quota_dirty(paths);
    let mut cands = pick_accounts(&gw, paths, &mut model, &skey, &mmode);

    if cands.is_empty() {
        // 缓存可能只是过期，别据此就判「号池没人可用」：先限时重取一轮全量额度再决定。
        // 不这么做就会出现「号今早 09:00 已重置、池子却说没号」—— 历史上 7364 次
        // `no-account` 里相当一部分是这个。等不到也照常回 502，刷新线程继续在后台跑。
        let ids: Vec<String> = store::list_accounts(paths)
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.id)
            .collect();
        if !ids.is_empty() && gw.refresh_accounts(paths, ids, EMPTY_WAIT_MS, "判空前确认") > 0 {
            cands = pick_accounts(&gw, paths, &mut model, &skey, &mmode);
        }
    }
    if cands.is_empty() {
        let at = now_ms();
        let n = store::list_accounts(paths).map(|v| v.len()).unwrap_or(0);
        crate::usage::append(&usage_path, &mk("", 502, "no-account", 0, false, at));
        // 别说「没有号」了事完 —— 号明明在池里，只是这一发排不上。说清是哪两种原因。
        let why = if n == 0 {
            "号池是空的 —— 先在「账号库」加号".to_string()
        } else {
            format!("{n} 个号都排不上 {model}：要么该模型没额度，要么正在冷却（刚重取过一轮额度，日志可查）")
        };
        return reply_json(
            slot.take().unwrap(),
            502,
            &json!({ "type": "error",
                     "error": { "type": "overloaded_error",
                                "message": why } }),
        );
    }

    let mut tried = 0usize;

    let mut last_abnormal: Option<(u16, Option<String>, Vec<u8>, Box<dyn std::io::Read + Send>)> = None;

    let mut last_acct = String::new();
    let mut last_at = now_ms();
    for c in cands.iter().take(MAX_TRIES) {
        tried += 1;

        // 2026-09-30 实测：**上游不再要求模型请求带一次性验证码**。
        //   带 → 200；不带（连打 5 发）→ 200；两者速度无可测差异
        //   （TTFB 中位差 36ms，远小于单次抖动 800~2100ms）。官方 3.14.4 更新日志也写了
        //   「关闭模型请求验证码校验」。所以这里不再取码、不再发那两个头。
        //
        // 副作用（正面的）：取码是**按需**的（`want_mint` 看 `waiters` / `last_use`），
        //   而 `last_use` 只由 `take_param` 更新 —— 不调它，180 秒后取码自动停，
        //   阿里云那边不再按次计费，也不用再动取码循环。
        //
        // ⚠ 领取套餐用的是**另一套**验证码（captcha.html 独立窗口 → claim_captcha_submit），
        //   不经过这里，**别一起删**。
        // 万一上游又要求了（症状：401/3012 且日志里没有 no-param 记录），恢复下面这段即可：
        //   let (param, region) = gw.take_param()?; // 并在下面的链式 .set 里带上这两个头
        let sess = account_session(&c.id, &day_seed());
        let out_body = match external_body(body, &c.mid, &model, &sess, paths) {
            Ok(b) => b,
            Err((code, e)) => {
                let ty = if code >= 500 {
                    "api_error"
                } else {
                    "invalid_request_error"
                };
                crate::usage::append(&usage_path, &mk(&c.name, code, "bad-body", tried, false, now_ms()));
                return reply_json(
                    slot.take().unwrap(),
                    code,
                    &json!({ "type": "error", "error": { "type": ty, "message": e } }),
                );
            }
        };

        // 头与真实转发共用 `set_relay_headers`：少一个头上游就可能判成异常请求，
        // 那样「对话测试」得出的结论不代表真实请求。
        let call = set_relay_headers(agent.request("POST", &target), &c.token);
        // 注：以前这里还有 x-aliyun-captcha-verify-param / -region 两个头，
        // 2026-09-30 起不再发（上游已关闭模型请求的验证码校验，见上方说明）。

        let tried_at = now_ms();
        last_acct = c.name.clone();
        last_at = tried_at;
        let (status, reader, ctype) = match call.send_bytes(&out_body) {
            Ok(r) => {
                let ct = r.header("Content-Type").map(|s| s.to_string());
                (r.status(), r.into_reader(), ct)
            }
            Err(ureq::Error::Status(code, r)) => {
                let ct = r.header("Content-Type").map(|s| s.to_string());
                (code, r.into_reader(), ct)
            }
            Err(e) => {
                crate::flowlog::log("relay", "external-fail", &format!("{} {e}", c.name));
                gw.mark_blocked(&c.id, RATE_TTL_MS);
                std::thread::sleep(Duration::from_millis(backoff_ms(tried)));
                continue;
            }
        };
        // ── 只有 2xx 才允许把上游应答交给调用方，其余一律本地回错。
        //    被拦时上游发的是整页 HTML，原样透传就成了客户端看到的「HTTP 405 <!doctypehtml>…」。
        //    更要紧的是分两类：**与号有关**的才换下一个试；**与号无关**的（路由被关、被边缘拦、
        //    上游自己挂了）换号只是把同一堵墙再撞一遍 —— 实测 405 三分钟内累计 2870 发。
        if !(200..300).contains(&status) {
            if SWITCH_STATUS.contains(&status) {
                // 四类一律冷却。以前只有 429 冷却，于是 401/402/403 的号既不冻结也不重取
                // 额度 —— 下一个请求仍从它开始，每一发都白烧一次往返。
                let cool = account_cooldown(status);
                gw.mark_blocked(&c.id, cool);
                if status == 401 {
                    // 401 = 这一发用的凭证不被认。要是这个号还存着「上次试通」的指纹，说明它
                    // 已经失效了（重新登录、token_version 被吊销都会这样）—— 清掉提示回到默认
                    // 顺序，让人再点一次对话测试重新认一个，而不是抱着坏提示一路 401。
                    gw.drop_plan_hint(paths, &c.id);
                }
                // 顺手把该号额度取回真实值：「用完」应当由刷新确认，而不是干等 5 分钟 TTL
                gw.refresh_accounts(paths, vec![c.id.clone()], 0, "上游拒绝");
                let d = backoff_ms(tried);
                crate::flowlog::log(
                    "relay",
                    "switch",
                    &format!(
                        "外部 {} HTTP {status} → 冷却 {}s 并换下一个（退避 {d}ms，已安排重取额度）",
                        c.name,
                        cool / 1000
                    ),
                );
                std::thread::sleep(Duration::from_millis(d));
                continue;
            }

            // 以下都与号无关：不再试别的号。先取一小段应答留作线索（限 600B，读不动就空着）。
            let mut snip: Vec<u8> = Vec::new();
            let _ = reader.take(600).read_to_end(&mut snip);
            let snip = crate::quota::body_snippet(&String::from_utf8_lossy(&snip));
            let (kind, ms) = upstream_verdict(status, &snip);
            if ms > 0 {
                gw.edge_trip(ms);
            }
            let verdict = if ms > 0 {
                format!("熔断 {}s，期间不出站", ms / 1000)
            } else {
                "不重试、不换号，直接回错".to_string()
            };
            crate::flowlog::log(
                "relay",
                "edge-block",
                &format!("外部 {} HTTP {status}｜{kind}｜{verdict}｜片段：{snip}", c.name),
            );
            crate::usage::append(&usage_path, &mk(&c.name, 503, "upstream-block", tried, false, tried_at));
            return reply_json(
                slot.take().unwrap(),
                503,
                &json!({ "type": "error",
                         "error": { "type": "overloaded_error",
                                    "message": format!("上游回 HTTP {status}：{kind} —— {verdict}。应答片段：{snip}") } }),
            );
        }
        // 到这里 status 必定是 2xx。

        let stream = ctype.as_deref().unwrap_or("").to_ascii_lowercase().contains("event-stream");
        let mut up: Option<String> = None;
        let mut reader: Box<dyn std::io::Read + Send> = Box::new(reader);
        if status == 200 {
            let ct_lower = ctype.as_deref().unwrap_or("").to_ascii_lowercase();
            let mut head: Vec<u8> = Vec::new();
            let mut buf = vec![0u8; 2048];
            let mut ended = false;
            let mut eof = false;
            for _ in 0..6 {
                match reader.read(&mut buf) {
                    Ok(0) => { eof = true; ended = true; break; }
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                    Err(_) => { ended = true; break; }
                }
                if peek_model(&head).is_some() || head.len() >= 4096 { break; }
            }

            up = peek_model(&head);
            let flat = String::from_utf8_lossy(&head)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            // 兜底：上游（或它前面的 CDN/边缘）也可能用 **200** 塞回一页 HTML 或一个空 body。
            // 那形状跟号无关，换下一个照样拿回同一页 —— 判成通道被拦，不透传也不换号。
            // 认 HTML 开头 / 首读即 EOF，别拿「认不出模型名」当依据：真流的前几行是
            // `event:` / `data:`，误判会把整池锁 60 秒。
            if up.is_none() && (flat.starts_with('<') || (eof && head.is_empty())) {
                gw.edge_trip(EDGE_COOLDOWN_MS);
                crate::flowlog::log(
                    "relay",
                    "edge-block",
                    &format!(
                        "外部 {} HTTP {status} 2xx 但应答不是模型流｜通道被拦（与号无关，换号无意义）｜熔断 {}s，期间不出站｜片段：{}",
                        c.name,
                        EDGE_COOLDOWN_MS / 1000,
                        crate::quota::body_snippet(&flat)
                    ),
                );
                crate::usage::append(&usage_path, &mk(&c.name, 503, "upstream-block", tried, false, tried_at));
                return reply_json(
                    slot.take().unwrap(),
                    503,
                    &json!({ "type": "error",
                             "error": { "type": "overloaded_error",
                                        "message": format!("上游回 HTTP {status} 但应答不是模型流（多半是被边缘拦下的页面），已熔断 {}s", EDGE_COOLDOWN_MS / 1000) } }),
                );
            }
            let txt = String::from_utf8_lossy(&head).to_lowercase();
            if up.is_none()
                && (ended || !ct_lower.contains("event-stream")
                    || txt.contains("\"error\"") || txt.contains("\"code\""))
            {
                let short: String = String::from_utf8_lossy(&head).chars().take(200).collect();
                crate::flowlog::log("relay", "abnormal",
                    &format!("外部 {} ctype={ct_lower} 响应不像模型流，换下一个：{short}", c.name));
                last_abnormal = Some((status, ctype.clone(), head, reader));
                continue;
            }
            reader = Box::new(std::io::Cursor::new(head).chain(reader));
        }
        gw.set_sticky(&skey, &c.id);
        {
            let mut g = gw.inner.lock().unwrap();
            g.served += 1;
            if tried > 1 {
                g.switched += 1;
            }
            g.last_route = Some(Route {
                account: c.id.clone(),
                model: model.clone(),
                tries: tried,
            });
        }
        crate::flowlog::log(
            "relay",
            "external-ok",
            &format!(
                "{} HTTP {status} model={model} tries={tried} len={}",
                c.name,
                out_body.len()
            ),
        );

        let mut hs: Vec<tiny_http::Header> = vec![];
        if let Some(ct) = ctype {
            if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()) {
                hs.push(h);
            }
        }
        for (k, v) in [
            ("x-relay-account", c.name.clone()),
            ("x-relay-tries", tried.to_string()),
        ] {
            if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                hs.push(h);
            }
        }
        let reader: Box<dyn std::io::Read + Send> = Box::new(Meter {
            inner: gw.inner.clone(),
            src: reader,
            tail: Vec::new(),
            head: Vec::new(),
            tokens: 0,
            tokens_in: 0,
            cache: 0,
            bytes: 0,
            started: tried_at,
            first_at: None,

            acct_id: c.id.clone(),
            up_model: model.clone(),

            rec: Some(crate::usage::UsageRecord {
                t: tried_at,
                acct: c.name.clone(),
                model: client_model.clone(),
                up,
                tokens_in: 0,
                tokens_out: 0,
                cache: 0,
                ttfb: None,
                ms: 0,
                bytes: 0,
                status,
                code: String::new(),
                tries: tried,
                stream,
                mapped: mapped.clone(),
                key: key_tag.to_string(),
            }),
            path: usage_path.clone(),
        });
        let resp =
            tiny_http::Response::new(tiny_http::StatusCode(status), hs, reader, None, None);
        let _ = slot.take().unwrap().respond(resp);
        return Ok(());
    }

    if let Some((status, ctype, head, reader)) = last_abnormal {
        let mut hs: Vec<tiny_http::Header> = vec![];
        if let Some(ct) = ctype {
            if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()) {
                hs.push(h);
            }
        }

        let mut rec = mk(
            &last_acct,
            status,
            "abnormal",
            tried,
            hs.iter().any(|h| h.value.as_str().to_ascii_lowercase().contains("event-stream")),
            last_at,
        );
        rec.up = peek_model(&head);
        rec.bytes = head.len() as u64;
        rec.ms = now_ms().saturating_sub(last_at);
        crate::usage::append(&usage_path, &rec);
        let rd: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(head).chain(reader));
        let resp = tiny_http::Response::new(tiny_http::StatusCode(status), hs, rd, None, None);
        let _ = slot.take().unwrap().respond(resp);
        crate::flowlog::log("relay", "abnormal-all", &format!("外部 tried={tried} path={path}"));
        return Ok(());
    }
    crate::usage::append(&usage_path, &mk(&last_acct, 502, "rejected", tried, false, last_at));
    reply_json(
        slot.take().unwrap(),
        502,
        &json!({ "type": "error",
                 "error": { "type": "overloaded_error",
                            "message": format!("试了 {tried} 个号都被拒") } }),
    )
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split('?').nth(1)?;
    for kv in q.split('&') {
        let (k, v) = match kv.split_once('=') {
            Some((k, v)) => (k, v),
            None => (kv, ""),
        };
        if k == key {
            return Some(decode_pct(v));
        }
    }
    None
}

fn decode_pct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn handle(mut req: tiny_http::Request, gw: &Gateway) -> Result<(), String> {
    let paths = Paths::detect();
    let url = req.url().to_string();
    let mut body = Vec::new();
    if req.as_reader().read_to_end(&mut body).is_err() {
        let _ = req.respond(tiny_http::Response::from_string("bad body").with_status_code(400));
        return Ok(());
    }

    let path = norm_path(&url);

    let from_loopback = req
        .remote_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(true);

    if !from_loopback && gw.inner.lock().unwrap().bind.starts_with("127.") {
        crate::flowlog::log("relay", "bind-deny", &format!("{path} 来自非本机，但当前是「仅本机」模式"));
        let _ = req.respond(
            tiny_http::Response::from_string("not found
").with_status_code(404),
        );
        return Ok(());
    }
    if !from_loopback {
        let keys = gw.inner.lock().unwrap().keys.clone();
        if keys.is_empty() {

            let _ = req.respond(
                tiny_http::Response::from_string("外部访问未启用：没有配置 API Key\n")
                    .with_status_code(401),
            );
            return Ok(());
        }
        let got = auth_token(&req);
        if !keys.iter().any(|k| *k == got) {
            crate::flowlog::log("relay", "auth-deny", &format!("{path} 凭据不对"));
            let _ = req.respond(
                tiny_http::Response::from_string("unauthorized：请在 x-api-key 或 Authorization 里带上 API Key\n")
                    .with_status_code(401),
            );
            return Ok(());
        }
    }

    let key_tag: String = {
        let t = auth_token(&req);
        if t.is_empty() { "本机".to_string() } else { t.chars().take(8).collect() }
    };

    match path.as_str() {
        "/" | "/chat" => return reply_html(req, page("chat.html", CHAT_PAGE)),
        "/proxy" | "/proxy/admin" => return reply_html(req, page("proxy.html", PROXY_PAGE)),
        "/proxy/status" => return reply_json(req, 200, &gw.console_status(&paths)),

        "/proxy/usage" => {
            let limit = query_param(&url, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .min(1000);
            let acct = query_param(&url, "acct").unwrap_or_default().to_lowercase();
            let model = query_param(&url, "model").unwrap_or_default().to_lowercase();
            let key = query_param(&url, "key").unwrap_or_default().to_lowercase();
            let ok = query_param(&url, "ok").unwrap_or_default();
            let rows = crate::usage::read_all(&crate::usage::path_for(&paths.store_dir()));
            let total = rows.len();
            let out: Vec<Value> = rows
                .iter()
                .rev()
                .filter(|r| acct.is_empty() || r.acct.to_lowercase() == acct)
                .filter(|r| {
                    model.is_empty()
                        || r.model.to_lowercase() == model
                        || r.up.as_deref().map(|u| u.to_lowercase() == model).unwrap_or(false)
                })
                .filter(|r| key.is_empty() || r.key.to_lowercase() == key)
                .filter(|r| match ok.as_str() {
                    "1" | "true" | "ok" => !crate::usage::is_fail(r),
                    "0" | "false" | "fail" => crate::usage::is_fail(r),
                    _ => true,
                })
                .take(limit)
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            let count = out.len();
            return reply_json(req, 200, &json!({ "rows": out, "count": count, "total": total }));
        }
        "/proxy/usage/stats" => {
            return reply_json(req, 200, &crate::usage::stats(&crate::usage::path_for(&paths.store_dir())));
        }

        "/proxy/logs" => {
            let offset = query_param(&url, "offset").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
            let limit = query_param(&url, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(50).clamp(1, 500);
            let (lines, total) = crate::flowlog::tail_page(offset, limit);
            return reply_json(req, 200, &json!({ "lines": lines, "total": total, "offset": offset, "limit": limit }));
        }

        "/proxy/probe" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let one = v.get("id").and_then(|x| x.as_str()).map(str::to_string);
            let ids: Vec<String> = match one {
                Some(id) => vec![id],
                None => store::list_accounts(&paths).unwrap_or_default().into_iter().map(|a| a.id).collect(),
            };
            let mut res = vec![];
            for id in ids.iter().take(30) {
                let r = gw.probe_one(&paths, id);
                res.push(json!({ "id": id, "ok": r.is_ok(), "ms": r.as_ref().ok(), "err": r.err() }));
            }
            return reply_json(req, 200, &json!({ "results": res, "status": gw.console_status(&paths) }));
        }
        "/proxy/chat-test" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if id.is_empty() {
                return reply_json(req, 400, &json!({ "error": "缺 id" }));
            }
            return reply_json(req, 200, &chat_test(gw, &paths, id));
        }

        "/proxy/bind" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let bind = v.get("bind").and_then(|x| x.as_str()).unwrap_or("");
            return match gw.set_bind(&paths, bind) {
                Ok(st) => reply_json(req, 200, &st),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/key-add" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let want = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
            return match gw.key_add(&paths, want) {
                Ok(k) => {
                    crate::flowlog::log("relay", "key-add", &format!("新建 API Key {}", k.chars().take(8).collect::<String>()));
                    reply_json(req, 200, &json!({ "key": k, "status": gw.console_status(&paths) }))
                }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/key-del" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let k = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
            let in_use = !gw.inner.lock().unwrap().bind.starts_with("127.");
            if in_use && gw.inner.lock().unwrap().keys.len() <= 1 {
                return reply_json(req, 400, &json!({ "error": "现在是局域网模式，删掉最后一个 key 会让人进不来（先把监听地址改回 127.0.0.1）" }));
            }
            return match gw.key_del(&paths, k) {
                Ok(_) => reply_json(req, 200, &gw.console_status(&paths)),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/model-map" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("");
            let to = v.get("to").and_then(|x| x.as_str()).unwrap_or("");
            return match gw.set_model_map(&paths, from, to) {
                Ok(st) => {
                    crate::flowlog::log("relay", "model-map-set", &format!("{from} -> {}", if to.is_empty() { "(删)" } else { to }));
                    reply_json(req, 200, &st)
                }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/external" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let on = v.get("on").and_then(|x| x.as_bool()).unwrap_or(false);
            match gw.set_external_and_run(&paths, on) {
                Ok(st) => {
                    crate::flowlog::log("relay", "external-set", &format!("网页把反代设为 {on}"));
                    return reply_json(req, 200, &st);
                }
                Err(e) => return reply_json(req, 400, &json!({ "error": e })),
            }
        }
        "/proxy/port" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            return match gw.set_port(&paths, port) {
                Ok(st) => {
                    crate::flowlog::log("relay", "port-set", &format!("网页把端口改成 {port}"));
                    reply_json(req, 200, &st)
                }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/refresh-quota" => {
            if let Err(e) = gw.refresh_quota(&paths, true) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }

        "/proxy/unfreeze" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                let n = gw.unfreeze(id);
                crate::flowlog::log("relay", "unfreeze", &format!("{id} 清了 {n} 条标记"));
            }
            if v.get("edge").and_then(Value::as_bool) == Some(true) {
                let left = gw.edge_reset();
                crate::flowlog::log(
                    "relay",
                    "unfreeze",
                    &format!("手动解除通道熔断（原本还剩 {}s）", left / 1000),
                );
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }

        "/proxy/policy" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let policy = v.get("policy").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let pinned = v.get("pinned").and_then(|x| x.as_str()).map(str::to_string);
            if policy.is_empty() {
                return reply_json(req, 400, &json!({ "error": "policy 不能为空" }));
            }
            if let Err(e) = gw.set_policy(policy, pinned) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }
        // 反代出站的代理（空字符串 = 改回直连）
        "/proxy/proxy-url" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if !url.is_empty() {
                if let Err(e) = crate::oauth::parse_proxy_url(&url) {
                    return reply_json(req, 400, &json!({ "error": e }));
                }
            }
            if let Err(e) = store::set_relay_proxy(&paths, &url) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            {
                let mut g = gw.inner.lock().unwrap();
                g.relay_proxy = if url.is_empty() { None } else { Some(url.clone()) };
            }
            crate::flowlog::log("relay", "proxy-set", &if url.is_empty() { "直连".into() } else { url });
            return reply_json(req, 200, &gw.console_status(&paths));
        }
        "/proxy/model-mode" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let mode = v.get("mode").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let pinned = v.get("pinned").and_then(|x| x.as_str()).map(|s| s.to_string());
            if let Err(e) = gw.set_model_mode(&paths, mode, pinned) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }

        "/client-log" => {
            if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("?");
                let detail = v.get("detail").and_then(|x| x.as_str()).unwrap_or("");
                crate::flowlog::log("chat", kind, &detail.chars().take(300).collect::<String>());
            }
            return reply_json(req, 200, &json!({ "ok": true }));
        }
        "/mint" => return reply_html(req, page("mint.html", MINT_PAGE)),
        "/want-mint" => {
            let v = gw.want_mint(url.contains("wait"));
            return reply_json(req, 200, &v);
        }
        "/mint-result" => {
            if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                let param = v.get("param").and_then(|p| p.as_str()).unwrap_or("").trim().to_string();
                let region = v
                    .get("region")
                    .and_then(|p| p.as_str())
                    .unwrap_or(CAPTCHA_REGION)
                    .to_string();
                if !param.is_empty() {
                    let cid = v.get("certifyId").and_then(|p| p.as_str()).unwrap_or("?").to_string();
                    let n = gw.put_param(param, region);
                    crate::flowlog::log("relay", "mint", &format!("+1 池={n} certifyId={cid}"));
                }
            }
            return reply_json(req, 200, &json!({ "ok": true }));
        }

        p if p == "/v1/models" || p == "/models" || p.starts_with("/v1/models/") || p.starts_with("/models/") => {
            let one = p.rsplit('/').next().unwrap_or("");
            let want = if p.starts_with("/v1/models/") || p.starts_with("/models/") {
                EXTERNAL_MODELS.iter().find(|m| m.eq_ignore_ascii_case(one)).copied()
            } else {
                None
            };
            if !one.is_empty() && !p.ends_with("/models") && want.is_none() {
                return reply_json(
                    req,
                    404,
                    &json!({ "type": "error",
                             "error": { "type": "not_found_error",
                                        "message": format!("没有这个模型：{one}（可用：{}）", EXTERNAL_MODELS.join(", ")) } }),
                );
            }
            let list: Vec<&str> = match want {
                Some(m) => vec![m],
                None => EXTERNAL_MODELS.to_vec(),
            };
            let data: Vec<Value> = list
                .iter()
                .map(|m| json!({ "id": m, "type": "model", "object": "model", "display_name": m, "created_at": 0 }))
                .collect();
            return reply_json(
                req,
                200,
                &json!({
                    "object": "list",
                    "type": "list",
                    "data": data,
                    "has_more": false,
                    "first_id": list.first().copied(),
                    "last_id": list.last().copied(),
                }),
            );
        }

        "/proxy/accounts" => {
            return match store::get_state(&paths) {
                Ok(st) => reply_json(req, 200, &json!(st)),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/quota" => {
            let id = query_param(&url, "id").unwrap_or_default();
            return match store::account_quota(&paths, &id) {
                Ok(q) => reply_json(req, 200, &json!(q)),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/capture" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let name = v.get("name").and_then(|x| x.as_str()).map(str::to_string).filter(|s| !s.trim().is_empty());
            let r = { let _g = crate::store_guard(); store::capture_current(&paths, name) };
            return match r {
                Ok(a) => { gw.sync_exe(); reply_json_masked(req, 200, &json!(a), from_loopback) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/rename" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let r = { let _g = crate::store_guard(); store::rename_account(&paths, &id, &name) };
            return match r {
                Ok(a) => { gw.sync_exe(); reply_json_masked(req, 200, &json!(a), from_loopback) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/delete" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let r = { let _g = crate::store_guard(); store::delete_account(&paths, &id) };
            return match r {
                Ok(()) => { gw.sync_exe(); reply_json(req, 200, &json!({ "ok": true, "status": gw.console_status(&paths) })) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/update-live" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let r = { let _g = crate::store_guard(); store::update_account_from_live(&paths, &id) };
            return match r {
                Ok(a) => { gw.sync_exe(); reply_json_masked(req, 200, &json!(a), from_loopback) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/switch" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let force = v.get("force").and_then(|x| x.as_bool()).unwrap_or(false);
            let restart = v.get("restart").and_then(|x| x.as_bool()).unwrap_or(true);
            let r = { let _g = crate::store_guard(); store::switch_to(&paths, &id, force, restart) };
            return match r {
                Ok(s) => { gw.sync_exe(); reply_json(req, 200, &json!({ "result": s, "status": gw.console_status(&paths) })) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/claim-preview" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mid = match store::account_mid(&paths, &id) { Ok(m) => m, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            let acc = match store::load_account(&paths, &id) { Ok(a) => a, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            return match crate::claim::preview_plans(&paths.home, &acc.credentials, acc.config.as_ref(), Some(mid)) {
                Ok(plans) => reply_json(req, 200, &json!({ "plans": plans })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/claim-refresh" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mid = match store::account_mid(&paths, &id) { Ok(m) => m, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            let acc = match store::load_account(&paths, &id) { Ok(a) => a, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            let (activated, activation_error) = match crate::claim::telemetry_user_id(&paths.home, &acc.credentials) {
                Some(uid) => match crate::claim::report_activation_events(&uid, &mid) {
                    Ok(()) => (true, None),
                    Err(e) => (false, Some(e)),
                },
                None => (false, None),
            };
            return match crate::claim::preview_plans(&paths.home, &acc.credentials, acc.config.as_ref(), Some(mid)) {
                Ok(plans) => reply_json(req, 200, &json!({ "plans": plans, "activated": activated, "activationError": activation_error })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/claim-start" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let plan_id = v.get("plan_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let auto = v.get("auto").and_then(|x| x.as_bool()).unwrap_or(true);
            let Some(app) = gw.app() else {
                return reply_json(req, 400, &json!({ "error": "反代还没拿到 AppHandle（窗口环境未就绪），这一步暂时只能在 exe 面板做" }));
            };
            return match crate::proxy_claim_start(&app, id, plan_id, auto) {
                Ok(v) => reply_json(req, 200, &v),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/claim-result" => {
            return reply_json(req, 200, &crate::claim_last_result());
        }

        "/proxy/zcode/launch" => {
            let (p, ok) = store::effective_zcode_path(&paths);
            if !ok {
                return reply_json(req, 400, &json!({ "error": format!("ZCode 路径无效：{p}") }));
            }
            return match store::launch_zcode(&p) {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true, "status": gw.console_status(&paths) })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/zcode/kill" => {
            return match store::kill_zcode() {
                Ok(_) => reply_json(req, 200, &json!({ "ok": true, "status": gw.console_status(&paths) })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/zcode/path" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let _g = crate::store_guard();
            let mut s = store::load_settings(&paths);
            s.zcode_path = store::normalize_zcode_path(&path);
            let r = store::save_settings(&paths, &s);
            drop(_g);
            return match r {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/accounts/export" => {
            let accounts = match store::list_accounts(&paths) { Ok(a) => a, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            if accounts.is_empty() {
                return reply_json(req, 400, &json!({ "error": "账号库是空的" }));
            }
            let mut payload = store::export_bundle_value(&accounts);
            if !from_loopback { mask_json(&mut payload); }
            let body = serde_json::to_string_pretty(&payload).unwrap_or_default() + "\n";
            return reply_text(req, body, "zcode-accounts.json");
        }

        "/proxy/mail" => {
            let root = paths.store_dir();
            let items: Vec<_> = crate::pool::load(&root).iter().map(|a| a.to_summary()).collect();
            return reply_json(req, 200, &json!({ "accounts": items }));
        }
        "/proxy/mail/get" => {
            let email = query_param(&url, "email").unwrap_or_default();
            let root = paths.store_dir();
            let accounts = crate::pool::load(&root);
            return match crate::pool::find(&accounts, &email) {
                Some(a) => reply_json_masked(req, 200, &json!({ "email": a.email, "password": a.password }), from_loopback),
                None => reply_json(req, 404, &json!({ "error": "邮箱不在库里" })),
            };
        }

        "/proxy/mail/import" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let raw = v.get("text").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let rep = crate::pool::import(&mut accounts, &raw, store::now_ts());
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(rep), Err(e) => Err(e) }
            };
            return match r {
                Ok(rep) => reply_json(req, 200, &json!({ "added": rep.added, "skipped": rep.skipped, "parsed": rep.total_parsed })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/remove" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let before = accounts.len();
                accounts.retain(|a| !a.email.eq_ignore_ascii_case(email.trim()));
                let removed = before - accounts.len();
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(removed), Err(e) => Err(e) }
            };
            return match r {
                Ok(n) => reply_json(req, 200, &json!({ "removed": n })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/remove-many" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let emails: Vec<String> = v.get("emails").and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_ascii_lowercase()).collect())
                .unwrap_or_default();
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let before = accounts.len();
                accounts.retain(|a| !emails.contains(&a.email.trim().to_ascii_lowercase()));
                let removed = before - accounts.len();
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(removed), Err(e) => Err(e) }
            };
            return match r {
                Ok(n) => reply_json(req, 200, &json!({ "removed": n })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/mark-verified" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(true);
            let note = v.get("note").and_then(|x| x.as_str()).map(str::to_string);
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                if let Some(a) = crate::pool::find_mut(&mut accounts, &email) {
                    if ok {
                        a.status = crate::pool::STATUS_VERIFIED.to_string();
                        a.verified_at = Some(store::now_ts());
                        a.note = None;
                    } else {
                        a.status = crate::pool::STATUS_FAILED.to_string();
                        a.note = note;
                    }
                    crate::pool::save(&root, &accounts)
                } else {
                    Ok(())
                }
            };
            return match r {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/reset" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let root = paths.store_dir();
            let r = { let _g = crate::store_guard(); crate::pool::set_status(&root, &email, crate::pool::STATUS_NEW, None) };
            return match r {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/upsert" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let line = v.get("line").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let Some((email, password, client_id, refresh_token)) = crate::pool::parse_lines(&line).into_iter().next() else {
                return reply_json(req, 400, &json!({ "error": "行格式不对，应为 email----password----client_id----refresh_token" }));
            };
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let updated = if let Some(a) = crate::pool::find_mut(&mut accounts, &email) {
                    a.password = password;
                    a.client_id = client_id;
                    a.refresh_token = refresh_token;
                    a.status = crate::pool::STATUS_NEW.to_string();
                    a.note = None;
                    true
                } else {
                    accounts.push(crate::pool::MailAccount {
                        email: email.clone(),
                        password,
                        client_id,
                        refresh_token,
                        status: crate::pool::STATUS_NEW.to_string(),
                        verified_at: None,
                        note: None,
                        created_at: store::now_ts(),
                    });
                    false
                };
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(updated), Err(e) => Err(e) }
            };
            return match r {
                Ok(updated) => reply_json(req, 200, &json!({ "email": email, "updated": updated })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/export" => {
            let root = paths.store_dir();
            let accounts = crate::pool::load(&root);
            if accounts.is_empty() {
                return reply_json(req, 400, &json!({ "error": "邮箱库是空的" }));
            }
            let body: String = if from_loopback {
                accounts.iter()
                    .map(|a| format!("{}----{}----{}----{}\n", a.email, a.password, a.client_id, a.refresh_token))
                    .collect()
            } else {

                accounts.iter()
                    .map(|a| format!("{}----{}----{}----{}\n", a.email, mask_secret(&a.password), a.client_id, mask_secret(&a.refresh_token)))
                    .collect()
            };
            return reply_text(req, body, "mailboxes.txt");
        }

        "/proxy/mail/messages" => {
            let email = query_param(&url, "email").unwrap_or_default();
            let top = query_param(&url, "top").and_then(|v| v.parse::<usize>().ok()).unwrap_or(15);
            let root = paths.store_dir();
            let accounts = crate::pool::load(&root);
            let acc = match crate::pool::find(&accounts, &email) {
                Some(a) => a.clone(),
                None => return reply_json(req, 404, &json!({ "error": "邮箱不在库里" })),
            };
            let (msgs, new_rt) = match crate::graph::fetch_messages(&acc.client_id, &acc.refresh_token, top) {
                Ok(v) => v,
                Err(e) => {
                    if crate::graph::is_credential_error(&e) {
                        let _ = crate::pool::set_status(&root, &email, crate::pool::STATUS_INVALID, Some("需要重新授权".to_string()));
                    }
                    return reply_json(req, 400, &json!({ "error": e }));
                }
            };
            if let Some(rt) = new_rt {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                if let Some(a) = crate::pool::find_mut(&mut accounts, &email) {
                    a.refresh_token = rt;
                    let _ = crate::pool::save(&root, &accounts);
                }
            }

            let out: Vec<Value> = msgs.iter().map(|m| json!({
                "id": m.id, "subject": m.subject, "from": m.from,
                "receivedAt": m.received_at, "preview": m.preview,
                "html": m.html, "text": m.text, "body": m.text,
                "links": m.links,
            })).collect();
            return reply_json(req, 200, &json!({ "messages": out, "count": out.len() }));
        }
        _ => {}
    }

    // 上游没有 count_tokens（实测原样转发拿回 Go 的裸文本 `404 page not found`，
    // 不是 Anthropic 形状的 JSON），客户端做上下文预算时会整轮失败。本地估一个。
    if path.ends_with("/count_tokens") {
        return reply_json(
            req,
            200,
            &json!({ "input_tokens": estimate_input_tokens(&body) }),
        );
    }

    if path.starts_with("/v1") {
        return handle_external(req, gw, &paths, &path, &body, &key_tag);
    }

    let _ = req.respond(
        tiny_http::Response::from_string("404 — / 是对话页，/proxy 是控制台\n")
            .with_status_code(404),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTML: &str = "<!doctypehtml><html lang=\"zh-cn\"><title>405</title>";
    const JSON: &str = "{\"code\":3012,\"message\":\"unusual activity\"}";

    #[test]
    fn blocked_path_trips_the_long_cooldown() {
        // 实测的那一发：边缘拦下的 405 + 整页 HTML
        assert_eq!(upstream_verdict(405, HTML).1, EDGE_COOLDOWN_MS);
        // 没列进 PATH_STATUS、但形状同样是「被拦下的一页 HTML」
        assert_eq!(upstream_verdict(418, HTML).1, EDGE_COOLDOWN_MS);
    }

    #[test]
    fn listed_route_level_codes_trip_even_with_a_json_body() {
        for code in [404u16, 405, 406, 410, 413, 415, 451, 501, 505] {
            assert_eq!(upstream_verdict(code, JSON).1, EDGE_COOLDOWN_MS, "{code}");
        }
    }

    #[test]
    fn upstream_failure_gets_the_short_cooldown() {
        assert_eq!(upstream_verdict(502, JSON).1, UPSTREAM_COOLDOWN_MS);
        assert_eq!(upstream_verdict(503, HTML).1, UPSTREAM_COOLDOWN_MS);
    }

    #[test]
    fn a_bad_request_from_one_client_must_not_freeze_the_pool() {
        // 没见过的 4xx：多半是这一发请求不对，熔断会把所有号一起锁住
        assert_eq!(upstream_verdict(400, JSON).1, 0);
        assert_eq!(upstream_verdict(422, HTML).1, EDGE_COOLDOWN_MS); // 但 HTML 仍按被拦处理
    }

    #[test]
    fn odd_statuses_are_rejected_without_retry_or_trip() {
        assert_eq!(upstream_verdict(302, JSON).1, 0);
        assert_eq!(upstream_verdict(200, JSON).1, 0); // 2xx 走不到这里，兜底也要给 0
        assert_eq!(upstream_verdict(100, "").1, 0);
    }

    #[test]
    fn only_401_and_403_mean_the_credential_is_wrong() {
        // 200/402/429/5xx 都表示「上游认了这个凭证」。把它们算成凭证失效，就会接着去试
        // 那条端点根本不认的 provider apiKey，最后报出一个假的 401 —— 线上真踩过。
        assert!(is_auth_rejected(401));
        assert!(is_auth_rejected(403));
        for st in [200u16, 402, 429, 500, 503] {
            assert!(!is_auth_rejected(st), "{st} 不该判成凭证失效");
        }
    }

    #[test]
    fn gap_label_stops_blaming_the_credential_when_upstream_is_busy() {
        assert!(probe_gap_label(429).contains("并发"));
        assert!(probe_gap_label(402).contains("额度"));
        assert!(probe_gap_label(503).contains("与凭证无关"));
        assert!(!probe_gap_label(200).contains("重新登录"), "200 出不了话不是凭证的事");
    }

    #[test]
    fn reply_shape_names_a_thinking_only_answer() {
        // 200 但没正文：得说清是「只有思考块」还是「空 content」，两者处置不一样
        assert_eq!(
            reply_shape(r#"{"content":[{"type":"thinking","thinking":"……"}],"stop_reason":"max_tokens"}"#),
            Some("只有思考块、没有正文 —— max_tokens 太小或模型正在思考")
        );
        assert_eq!(reply_shape(r#"{"content":[],"stop_reason":"refusal"}"#), Some("有 content 数组但里面没有正文"));
        assert_eq!(reply_shape(r#"{"content":[{"type":"text","text":"hi"}]}"#), None);
        assert_eq!(reply_shape("<!doctype html><html"), None, "被截断的片段解析不动，返回 None 就好");
    }

    #[test]
    fn upstream_business_codes_get_named() {
        assert_eq!(
            upstream_why(r#"{"code":3009,"msg":"model concurrency limit exceeded"}"#).as_deref(),
            Some("并发超限 —— 同一个号的模型并发被占满（例：这个号正在官方客户端里用）（code 3009）")
        );
        assert!(upstream_why(r#"{"code":3012,"msg":"unusual activity"}"#).unwrap().contains("3012"));
        assert_eq!(upstream_why("<!doctype html><title>405</title>"), None, "HTML 没有业务码");
        assert_eq!(upstream_why("{}"), None);
    }

    #[test]
    fn production_and_probe_read_one_cooldown_rule() {
        assert_eq!(account_cooldown(429), RATE_TTL_MS);
        assert_eq!(account_cooldown(401), AUTH_COOLDOWN_MS);
        assert!(AUTH_COOLDOWN_MS < RATE_TTL_MS, "凭证类失败不该把只有一个号的池子冻满五分钟");
    }

    #[test]
    fn token_hint_picks_the_credential_that_actively_worked() {
        // 这就是线上那三个号的形状：#1 是 provider apiKey（端点不认），#2 才是 JWT
        let toks = vec!["apikey-that-endpoint-rejects".to_string(), "eyJhbGciOiJIUzI1NiJ9.jwt".to_string()];
        assert_eq!(pick_token_index(&toks, None), 0, "没记过就按默认顺序");
        let good = token_sha16(&toks[1]);
        assert_eq!(pick_token_index(&toks, Some(&good)), 1, "记住是第 2 份就用第 2 份");
        assert_eq!(pick_token_index(&toks, Some(&token_sha16(&toks[0]))), 0);
    }

    #[test]
    fn stale_token_hint_falls_back_instead_of_locking_the_account_out() {
        let toks = vec!["a-long-enough-token-value".to_string()];
        // 凭证被重新登录换掉之后，记着的指针对不上 —— 只能退回默认顺序，不能因此不给发
        assert_eq!(pick_token_index(&toks, Some("0000000000000000")), 0);
        assert_eq!(pick_token_index(&toks, Some("")), 0);
        assert_eq!(pick_token_index(&[], Some(&token_sha16("x"))), 0);
        assert_ne!(token_sha16("a"), token_sha16("b"), "指纹得真能区分不同凭证");
        assert_eq!(token_sha16("a").len(), 16);
    }

    #[test]
    fn account_level_codes_stay_out_of_the_block_table() {
        // 401/402/403/429 归 SWITCH_STATUS（换号），绝不该同时出现在通道级表里
        for code in SWITCH_STATUS {
            assert!(!PATH_STATUS.contains(&code), "{code}");
        }
    }

    #[test]
    fn breaker_holds_until_manual_release() {
        let mut e = Edge::default();
        assert_eq!(e.waiting(1_000), None);

        e.trip(1_000, 60_000);
        assert_eq!(e.left(1_000), 60_000);
        // 第一次挡下记一条日志，之后同一轮的挡下不得再刷
        assert_eq!(e.waiting(2_000), Some((59_000, true)));
        assert_eq!(e.waiting(3_000), Some((58_000, false)));

        assert_eq!(e.reset(10_000), 51_000, "解除应当报告原本还剩多久");
        assert_eq!(e.waiting(11_000), None);
        assert_eq!(e.reset(12_000), 0, "重复解除不该留下脏状态");
    }

    #[test]
    fn tripping_again_extends_and_rearms_the_one_shot_log() {
        let mut e = Edge::default();
        e.trip(1_000, 60_000);
        assert_eq!(e.waiting(2_000), Some((59_000, true)));
        // 熔断没结束又撞一发别的（如 5xx 的短熔断）：以新窗口为准，并允许再记一条
        e.trip(3_000, 15_000);
        assert_eq!(e.left(3_000), 15_000);
        assert_eq!(e.waiting(4_000), Some((14_000, true)));
        assert_eq!(e.waiting(5_000), Some((13_000, false)));
    }

    #[test]
    fn an_expired_window_stops_blocking_without_clearing_the_armed_flag() {
        let mut e = Edge::default();
        e.trip(0, 100);
        assert_eq!(e.waiting(50), Some((50, true)));
        assert_eq!(e.waiting(200), None, "过期就不再挡请求");
        assert_eq!(e.left(200), 0);
    }

    fn item(name: &str, remaining: f64, total: f64) -> crate::quota::QuotaItem {
        crate::quota::QuotaItem {
            name: name.to_string(),
            total: Some(total),
            used: Some(total - remaining),
            remaining: Some(remaining),
            percent_used: Some((total - remaining) / total * 100.0),
            unit: "token".to_string(),
            ..Default::default()
        }
    }

    /// 真实形状：`candidates` 只读 `plans`，`items` 是给界面显示的，两边必须同步扣
    fn overview(items: Vec<crate::quota::QuotaItem>) -> crate::quota::QuotaOverview {
        let plans = vec![crate::quota::PlanSlot {
            expire: Some("2026-10-26 09:00".to_string()),
            items: items.clone(),
            ..Default::default()
        }];
        crate::quota::QuotaOverview { items, plans, ..Default::default() }
    }

    #[test]
    fn drain_only_touches_the_matched_model_and_both_copies() {
        let mut ov = overview(vec![item("GLM-5.3-Flash", 100.0, 300.0), item("GLM-5.3", 50.0, 200.0)]);
        assert!(!drain_cached(&mut ov, "GLM-5.3-Flash", 40));
        assert_eq!(ov.items[0].remaining, Some(60.0));
        assert_eq!(ov.plans[0].items[0].remaining, Some(60.0), "plans 不扣的话下一发仍按旧余量选号");
        assert_eq!(ov.items[1].remaining, Some(50.0), "别的档不该动");
        assert_eq!(ov.items[0].used, Some(240.0));
        assert_eq!(ov.items[0].percent_used, Some(80.0));
    }

    #[test]
    fn drain_floors_at_zero_and_reports_the_doubt() {
        let mut ov = overview(vec![item("GLM-5.3-Flash", 10.0, 300.0)]);
        assert!(drain_cached(&mut ov, "GLM-5.3-Flash", 999), "扣穿要回报，让调用方去刷新确认");
        assert_eq!(ov.items[0].remaining, Some(0.0), "不许出现负余量");
        assert_eq!(ov.items[0].used, Some(300.0));
        assert_eq!(ov.items[0].percent_used, Some(100.0));
    }

    #[test]
    fn drain_ignores_spending_it_cannot_attribute() {
        let mut ov = overview(vec![item("GLM-5.3", 50.0, 200.0)]);
        assert!(!drain_cached(&mut ov, "GLM-5.3", 0), "没花钱不该动");
        assert!(!drain_cached(&mut ov, "GLM-4.5-Air", 500), "对不上档名不该动");
        assert_eq!(ov.items[0].remaining, Some(50.0));
        let mut bare = crate::quota::QuotaOverview::default();
        assert!(!drain_cached(&mut bare, "GLM-5.3", 10));
    }

    #[test]
    fn session_key_keeps_a_growing_conversation_on_the_same_account() {
        let a = r#"{"model":"GLM-5.3-Flash","system":[{"type":"text","text":"你是 X"}],"messages":[{"role":"user","content":"第一条"}]}"#;
        let b = r#"{"model":"GLM-5.3-Flash","system":[{"type":"text","text":"你是 X"}],"messages":[{"role":"user","content":"第一条"},{"role":"assistant","content":"答"},{"role":"user","content":"再来"}]}"#;
        let other = r#"{"system":[{"type":"text","text":"你是 X"}],"messages":[{"role":"user","content":"另一个问题"}]}"#;
        assert_eq!(session_key(a.as_bytes(), "k1"), session_key(b.as_bytes(), "k1"), "对话加长必须还钉在同一个号上（prompt 缓存局部性）");
        assert_ne!(session_key(a.as_bytes(), "k1"), session_key(a.as_bytes(), "k2"), "不同 API Key 要分摊到不同号");
        assert_ne!(session_key(a.as_bytes(), "k1"), session_key(other.as_bytes(), "k1"));
    }

    #[test]
    fn a_new_session_prefers_an_account_nobody_else_holds() {
        let cand = |id: &str| Candidate {
            id: id.to_string(),
            name: id.to_string(),
            token: String::new(),
            mid: String::new(),
            expire: None,
            left: 0.0,
        };
        let list = vec![cand("A"), cand("B"), cand("C")];
        let used = |ids: &[&str]| -> std::collections::HashSet<String> {
            ids.iter().map(|s| s.to_string()).collect()
        };

        assert_eq!(pick_for_new_session(&list, &used(&[])), 0, "全新池子用队首");
        assert_eq!(pick_for_new_session(&list, &used(&["A"])), 1, "A 被占了就给 B，别继续挤 A");
        assert_eq!(pick_for_new_session(&list, &used(&["A", "B"])), 2);
        assert_eq!(pick_for_new_session(&list, &used(&["A", "B", "C"])), 0, "全被占用就回队首：共用好过把请求判成空池");
    }

    #[test]
    fn reply_text_prefers_the_json_content_block() {
        let j = r#"{"id":"x","model":"GLM-5.3","content":[{"type":"text","text":"你好，我在"}]}"#;
        assert_eq!(extract_reply_text(j).as_deref(), Some("你好，我在"));
        // 转义要还原，不然引号后面就断了
        let q = r#"{"content":[{"type":"text","text":"他说\"好\"完"}]}"#;
        assert_eq!(extract_reply_text(q).as_deref(), Some("他说\"好\"完"));
    }

    #[test]
    fn reply_text_falls_back_to_scanning_an_sse_body() {
        let sse = "event: content_block_start\ndata: {\"type\":\"text\",\"text\":\"流式答复\"}\n\n";
        assert_eq!(extract_reply_text(sse).as_deref(), Some("流式答复"));
    }

    #[test]
    fn reply_text_reports_none_when_the_model_said_nothing() {
        assert_eq!(extract_reply_text("<!doctype html><html><body>blocked</body></html>"), None, "拦截页不是回复");
        assert_eq!(extract_reply_text(""), None);
        assert_eq!(extract_reply_text(r#"{"type":"error","error":{"type":"overloaded_error","message":"x"}}"#), None);
        assert_eq!(extract_reply_text(r#"{"content":[{"type":"text","text":"   "}]}"#), None, "空白不算答复");
        assert_eq!(extract_reply_text(r#"{"content":[]}"#), None);
    }

    #[test]
    fn reply_text_is_capped_for_display() {
        let long = format!(r#"{{"content":[{{"type":"text","text":"{}"}}]}}"#, "字".repeat(400));
        let t = extract_reply_text(&long).unwrap();
        assert_eq!(t.chars().count(), 160, "行内标签只放得下一小段");
    }

    #[test]
    fn session_key_declines_to_pin_what_it_cannot_read() {
        assert_eq!(session_key(b"not json", "k"), "", "解析不出来就不加粘性");
        assert_eq!(session_key(b"", "k"), "");
        let empty_msgs = r#"{"model":"GLM-5.3","messages":[]}"#;
        assert_eq!(session_key(empty_msgs.as_bytes(), "k"), "", "空对话钉不出意义，全落一个常量指纹反而更糟");
        let blanks = r#"{"system":"","messages":[{"content":"  "}]}"#;
        assert_eq!(session_key(blanks.as_bytes(), "k"), "", "只有空白文本也算读不到");
    }
}
