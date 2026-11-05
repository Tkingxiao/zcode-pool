use crate::quota;
use crate::zcrypto;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

pub const BILLING_CLAIM_URL: &str = "https://zcode.z.ai/api/v1/zcode-plan/billing/claim";
pub const CLIENT_CONFIGS_URL: &str = "https://zcode.z.ai/api/v1/client/configs";

/// 2026-11-05：**可领资格不在 `billing/preview`，在这条投放里**。
///
/// 实测：`billing/preview` 对所有号都只回 `{"code":0,"msg":""}` —— 连 `data` 都没有（换凭证、
/// 换 `platform`、换 `app_version`、带不带 mid 都一样；官方客户端自己把这种应答当错误抛，
/// 见 app.asar 里的 `manual_claim_preview_missing_data`）。于是工具的「查可领套餐」永远是 0 个，
/// 手动领取也走不到 POST（`claim_start_inner` 要先在列表里找 plan_id）。
///
/// 而 `/api/v1/marketing/touch?seq=n` 给未领的号回一条 delivery：
/// `banner.buttons[].action = { type: "claim_zcode_plan", args: { plan_id } }`，
/// 完整套餐对象在 `banner.background.bundle.args.zcode_plan`（plan_id / name / priority /
/// starts_at / ends_at / entitlements[]，字段与 billing 那边一致，直接复用 `parse_plan`）；
/// 已经领过的号 `deliveries` 是空数组。
///
/// ⚠ 只有带 `claim_zcode_plan` 按钮的投放才算「可领」：别的活动里塞的 plan 不能替用户点。
pub const MARKETING_TOUCH_URL: &str = "https://zcode.z.ai/api/v1/marketing/touch";

/// 客户端带的是自增 seq（`seq=0,1,2…`），这里给一个进程内的递增计数就够。
static TOUCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const CLAIM_TIMEOUT_SECS: u64 = 25;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ClaimGrant {
    pub name: String,
    pub units: f64,
    pub period: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ClaimPlan {
    pub plan_id: String,
    pub name: String,
    pub description: String,
    pub priority: i64,
    pub grants: Vec<String>,
    #[serde(default)]
    pub grant_items: Vec<ClaimGrant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptchaConfig {
    pub enabled: bool,
    pub region: String,
    pub prefix: String,
    pub scene_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimOutcome {
    pub account_id: String,
    pub account_name: String,
    pub plan_name: String,
    pub starts_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub server_time: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ClaimError {
    pub code: i64,
    pub message: String,
    pub next_at: Option<i64>,
}

impl From<String> for ClaimError {
    fn from(message: String) -> Self {
        ClaimError {
            code: -1,
            message,
            next_at: None,
        }
    }
}

fn claim_error(code: i64, body: &Value) -> ClaimError {
    let next_at = if code == 1005 {
        body.pointer("/data/plan/ends_at")
            .and_then(|x| x.as_i64())
            .map(|s| s * 1000)
    } else {
        None
    };
    ClaimError {
        code,
        message: failure_message(code, body),
        next_at,
    }
}

pub fn failure_payload(
    account_id: &str,
    account_name: &str,
    plan_name: &str,
    err: &ClaimError,
) -> Value {
    serde_json::json!({
        "ok": false,
        "accountId": account_id,
        "accountName": account_name,
        "planName": plan_name,
        "code": err.code,
        "nextAt": err.next_at,
        "message": err.message,
    })
}

fn claim_token(creds: &Value, config: Option<&Value>, secret: &str) -> Result<String, String> {
    let jwt = creds
        .get("zcodejwttoken")
        .and_then(|v| v.as_str())
        .and_then(|v| decrypt_credential(v, secret));
    if let Some(t) = jwt.filter(|t| t.trim().len() > 20) {
        return Ok(t);
    }
    if let Some(t) = quota::zai_billing_token(creds, config, secret) {
        return Ok(t);
    }
    Err(crate::i18n::tr("err.claim.no_jwt"))
}

fn decrypt_credential(v: &str, secret: &str) -> Option<String> {
    if zcrypto::is_encrypted(v) {
        zcrypto::decrypt_with_secret(v, secret).ok()
    } else {
        Some(v.to_string())
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(CLAIM_TIMEOUT_SECS))
        .build()
}

pub const EVENT_REPORT_URL: &str = "https://zcode.z.ai/api/v1/event/report";
pub const ACTIVATION_EVENTS: [&str; 3] = ["app_launch", "app_daily_active", "app_login_success"];
const SCREEN_RESOLUTION: &str = "2560x1440";
const ACTIVATION_TIMEOUT_SECS: u64 = 10;

pub(crate) fn telemetry_user_id(home: &Path, creds: &Value) -> Option<String> {
    let secret = zcrypto::default_secret(home);
    let provider = creds
        .get("oauth:active_provider")
        .and_then(|v| v.as_str())
        .and_then(|v| decrypt_credential(v, &secret))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "zai".to_string());
    let raw = creds
        .get(format!("oauth:{provider}:user_info"))?
        .as_str()?;
    let plain = decrypt_credential(raw, &secret)?;
    let info: Value = serde_json::from_str(&plain).ok()?;
    let pick = |k: &str| {
        info.get(k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    pick("id").or_else(|| pick("user_id")).map(String::from)
}

fn activation_event_body(element: &str, event_id: &str, user_id: &str, mid: &str) -> Value {
    let (region, extra) = match element {
        "app_login_success" => ("app_profile", serde_json::json!({ "login_provider": "zai" })),
        _ => ("app", serde_json::json!({})),
    };
    serde_json::json!({
        "event_id": event_id,
        "client_timezone": quota::client_timezone(),
        "client_language": quota::ZCODE_LANG,
        "element_name": element,
        "event_region": region,
        "event_type": "view",
        "event_text": "",
        "event_extra_detail": extra,
        "user_id": user_id,
        "screen_resolution": SCREEN_RESOLUTION,
        "app_version": quota::zcode_app_version(),
        "device_os_category": device_os_category(),
        "device_os_version": quota::os_version().unwrap_or_default(),
        "device_mid": mid,
        "mac_id": "",
        "marketing_params": "{}",
    })
}

fn device_os_category() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        _ => "linux",
    }
}

pub fn report_activation_events(user_id: &str, device_mid: &str) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(ACTIVATION_TIMEOUT_SECS))
        .build();
    for (i, element) in ACTIVATION_EVENTS.iter().enumerate() {
        let critical = i == 0;
        let body = activation_event_body(
            element,
            &uuid::Uuid::new_v4().to_string(),
            user_id,
            device_mid,
        );
        let resp = match agent
            .post(EVENT_REPORT_URL)
            .set("Content-Type", "application/json")
            .send_json(body)
        {
            Ok(r) => r,
            Err(e) => {
                if critical {
                    return Err(crate::i18n::trf(
                        "err.claim.activate_req",
                        &[("e", http_err("", e).trim())],
                    ));
                }
                continue;
            }
        };
        let text = match resp.into_string() {
            Ok(t) => t,
            Err(e) => {
                if critical {
                    return Err(crate::i18n::trf(
                        "err.claim.activate_req",
                        &[("e", &e.to_string())],
                    ));
                }
                continue;
            }
        };
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        if code != 0 && critical {
            return Err(failure_message(code, &v));
        }
    }
    Ok(())
}

pub fn preview_plans(
    home: &Path,
    creds: &Value,
    config: Option<&Value>,
    device_mid: Option<String>,
) -> Result<Vec<ClaimPlan>, String> {
    let secret = zcrypto::default_secret(home);
    let token = claim_token(creds, config, &secret)?;
    let seq = TOUCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let url = format!("{MARKETING_TOUCH_URL}?seq={seq}");
    let mut req = agent().get(&url);
    for (k, v) in quota::zai_billing_headers_with_mid(&token, device_mid) {
        req = req.set(&k, &v);
    }
    let resp = req
        .call()
        .map_err(|e| http_err(&crate::i18n::tr("err.claim.touch_req"), e))?
        .into_string()
        .map_err(|e| crate::i18n::trf("err.http.read", &[("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        return Err(failure_message(code, &v));
    }
    let deliveries = v
        .pointer("/data/deliveries")
        .and_then(Value::as_array)
        // 空数组 = 这个号确实没有可领（已领过的号就是这样）；
        // **没有 data 是另一回事** —— 那是应答缺字段，报出来，别替上游说「你没资格」。
        .ok_or_else(|| crate::i18n::tr("err.claim.touch_no_data"))?;
    Ok(plans_from_deliveries(deliveries))
}

/// 投放 → 可领套餐：只认**带 `claim_zcode_plan` 按钮**的那几档，且 plan_id 要对得上。
/// 别的活动里塞的套餐不能替用户点，所以宁可不显示。
fn plans_from_deliveries(deliveries: &[Value]) -> Vec<ClaimPlan> {
    let mut out: Vec<ClaimPlan> = Vec::new();
    for d in deliveries {
        let mut wanted: Vec<String> = Vec::new();
        collect_claim_plan_ids(d, &mut wanted);
        if wanted.is_empty() {
            continue;
        }
        let mut found: Vec<&Value> = Vec::new();
        collect_zcode_plans(d, &mut found);
        for p in found.iter().filter_map(|p| parse_plan(p)) {
            if wanted.iter().any(|w| *w == p.plan_id) && !out.iter().any(|e| e.plan_id == p.plan_id) {
                out.push(p);
            }
        }
    }
    out.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.plan_id.cmp(&b.plan_id)));
    out
}

fn collect_claim_plan_ids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            if m.get("type").and_then(Value::as_str) == Some("claim_zcode_plan") {
                if let Some(id) = m
                    .get("args")
                    .and_then(|a| a.get("plan_id"))
                    .and_then(Value::as_str)
                {
                    let id = id.trim().to_string();
                    if !id.is_empty() {
                        out.push(id);
                    }
                }
            }
            for x in m.values() {
                collect_claim_plan_ids(x, out);
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_claim_plan_ids(x, out);
            }
        }
        _ => {}
    }
}

/// 套餐对象挂在投放的展示资源里（banner / hero 的 `args.zcode_plan`），层级会变，
/// 所以按**键名**递归找，而不是写死一条 pointer 路径。
fn collect_zcode_plans<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "zcode_plan" {
                    out.push(x);
                }
                collect_zcode_plans(x, out);
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_zcode_plans(x, out);
            }
        }
        _ => {}
    }
}

fn http_err(prefix: &str, e: ureq::Error) -> String {
    if let ureq::Error::Status(code, resp) = e {
        let body = resp.into_string().unwrap_or_default();
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| ["msg", "message", "error"]
                .iter()
                .find_map(|k| v.get(k).and_then(|x| x.as_str()).map(String::from)))
            .unwrap_or_else(|| crate::quota::body_snippet(&body));
        return format!("{prefix} HTTP {code}: {msg}");
    }
    format!("{prefix} {e}")
}

pub fn submit_claim(
    home: &Path,
    creds: &Value,
    config: Option<&Value>,
    plan_id: &str,
    captcha_param: &str,
    captcha_region: Option<&str>,
    device_mid: Option<String>,
) -> Result<Value, ClaimError> {
    if captcha_param.trim().is_empty() {
        return Err(crate::i18n::tr("err.claim.no_captcha").into());
    }
    let secret = zcrypto::default_secret(home);
    let token = claim_token(creds, config, &secret)?;
    let mut req = agent().post(BILLING_CLAIM_URL);
    for (k, v) in quota::zai_billing_headers_with_mid(&token, device_mid) {
        req = req.set(&k, &v);
    }
    req = req.set("X-Aliyun-Captcha-Verify-Param", captcha_param.trim());
    if let Some(r) = captcha_region.filter(|r| !r.trim().is_empty()) {
        req = req.set("X-Aliyun-Captcha-Verify-Region", r.trim());
    }
    let resp = req
        .send_json(serde_json::json!({ "plan_id": plan_id }))
        .map_err(|e| ClaimError {
            code: -1,
            message: http_err(&crate::i18n::tr("err.claim.claim_req"), e),
            next_at: None,
        })?
        .into_string()
        .map_err(|e| ClaimError {
            code: -1,
            message: crate::i18n::trf("err.http.read", &[("e", &e.to_string())]),
            next_at: None,
        })?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        return Err(claim_error(code, &v));
    }
    Ok(v)
}

pub fn fetch_captcha_config() -> Result<CaptchaConfig, String> {
    let mut req = agent().get(CLIENT_CONFIGS_URL);
    for (k, v) in quota::zai_billing_headers("") {
        req = req.set(&k, &v);
    }
    let resp = req
        .call()
        .map_err(|e| crate::i18n::trf("err.claim.config_req", &[("e", &e.to_string())]))?
        .into_string()
        .map_err(|e| crate::i18n::trf("err.http.read", &[("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    if v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1) != 0 {
        return Err(crate::i18n::tr("err.claim.config_unavailable"));
    }
    let c = v.pointer("/data/configs/captcha").cloned().unwrap_or(Value::Null);
    let s = |k: &str| c.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    Ok(CaptchaConfig {
        enabled: c.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
        region: s("region"),
        prefix: s("prefix"),
        scene_id: s("sceneId"),
    })
}

fn str_field<'a>(e: &'a Value, snake: &str, camel: &str) -> Option<&'a str> {
    e.get(snake)
        .and_then(|v| v.as_str())
        .or_else(|| e.get(camel).and_then(|v| v.as_str()))
}

fn num_field(e: &Value, snake: &str, camel: &str) -> Option<f64> {
    e.get(snake)
        .and_then(|v| v.as_f64())
        .or_else(|| e.get(camel).and_then(|v| v.as_f64()))
}

fn parse_plan(p: &Value) -> Option<ClaimPlan> {
    let plan_id = str_field(p, "plan_id", "planId")?.trim().to_string();
    if plan_id.is_empty() {
        return None;
    }
    let grant_items: Vec<ClaimGrant> = p
        .get("entitlements")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|e| {
                    str_field(e, "meter", "meter") == Some("model_usage")
                        && str_field(e, "unit_type", "unitType") == Some("token")
                        && str_field(e, "show_name", "showName")
                            .map(|s| !s.trim().is_empty())
                            .unwrap_or(false)
                })
                .map(|e| ClaimGrant {
                    name: str_field(e, "show_name", "showName").unwrap_or("").to_string(),
                    units: num_field(e, "grant_units", "grantUnits").unwrap_or(0.0),
                    period: str_field(e, "period", "period").unwrap_or("one_time").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    let grants = grant_items
        .iter()
        .map(|g| {
            let period_cn = match g.period.as_str() {
                "daily" => "每日",
                "weekly" => "每周",
                "monthly" => "每月",
                _ => "一次性",
            };
            format!("{} · {} Token（{period_cn}）", g.name, fmt_units(g.units))
        })
        .collect();
    Some(ClaimPlan {
        name: p.get("name").and_then(|s| s.as_str()).unwrap_or("").trim().to_string(),
        description: p
            .get("description")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        priority: p.get("priority").and_then(|x| x.as_i64()).unwrap_or(0),
        plan_id,
        grants,
        grant_items,
    })
}

fn fmt_units(n: f64) -> String {
    let trim = |x: f64| {
        let r = (x * 10.0).round() / 10.0;
        if (r - r.trunc()).abs() < f64::EPSILON {
            format!("{}", r.trunc() as i64)
        } else {
            format!("{r:.1}")
        }
    };
    if n >= 1e6 {
        format!("{}M", trim(n / 1e6))
    } else if n >= 1e3 {
        format!("{}K", trim(n / 1e3))
    } else {
        format!("{}", n.round() as i64)
    }
}

pub fn failure_message(code: i64, body: &Value) -> String {
    let server_msg = ["msg", "message"]
        .iter()
        .find_map(|k| body.get(k).and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_default();
    let base = crate::i18n::tr(match code {
        1001 => "claim.fail.1001",
        1002 => "claim.fail.1002",
        1003 => "claim.fail.1003",
        1004 => "claim.fail.1004",
        1005 => "claim.fail.1005",
        3001 => "claim.fail.3001",
        3007 => "claim.fail.3007",
        401 => "claim.fail.401",
        _ => "claim.fail.generic",
    });
    if server_msg.is_empty() {
        base
    } else {
        crate::i18n::trf("claim.fail.with_server", &[("base", &base), ("server_msg", &server_msg)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-05 从「178」号真实投放里原样摘下来的结构（去掉与判定无关的样式字段）
    const TOUCH: &str = r#"{
      "code":0,"msg":"","data":{"server_time":1793893803,"language":"zh-CN","deliveries":[
        {"campaign_id":"2101141259813175296","resource_position":"banner","priority":50,
         "banner":{
           "buttons":[
             {"action":{"type":"close","args":null}},
             {"action":{"type":"claim_zcode_plan","args":{"plan_id":"zcode-v3-start-plan-1105"}}}],
           "background":{"type":"bundle","bundle":{
             "bundle":{"src":"https://cdn-zcode.z.ai/marketing/touch/assets/x.zip","entry":"index.html"},
             "args":{"zcode_plan":{"plan_id":"zcode-v3-start-plan-1105","name":"ZCODE GLOBAL BUILD",
               "priority":111,"starts_at":1793876400,"ends_at":1793926800,
               "entitlements":[{"entitlement_id":"ent-zcode-v3-start-plan-1105-1",
                 "show_name":"GLM-5.3-Flash","meter":"model_usage","unit_type":"token",
                 "grant_units":300000000,"period":"one_time","priority":101}]}}}}}}]}}"#;

    fn deliveries(v: &Value) -> Vec<Value> {
        v.pointer("/data/deliveries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn finds_the_claimable_plan_in_a_real_delivery() {
        let v: Value = serde_json::from_str(TOUCH).unwrap();
        let plans = plans_from_deliveries(&deliveries(&v));
        assert_eq!(plans.len(), 1, "真实投放里那一档应当被认出来");
        let p = &plans[0];
        assert_eq!(p.plan_id, "zcode-v3-start-plan-1105");
        assert_eq!(p.name, "ZCODE GLOBAL BUILD");
        assert_eq!(p.priority, 111);
        assert_eq!(p.grants.len(), 1);
        assert!(p.grants[0].contains("300M"), "{:?}", p.grants[0]);
        assert!(p.grants[0].contains("GLM-5.3-Flash"), "{:?}", p.grants[0]);
    }

    #[test]
    fn a_plan_without_a_claim_button_is_not_offered() {
        // 别的活动里也可能塞着套餐对象：没有 claim_zcode_plan 按钮就不能替用户点
        let v: Value = serde_json::from_str(
            r#"{"deliveries":[{"banner":{"background":{"bundle":{"args":{"zcode_plan":{
              "plan_id":"p-quiet","name":"偷偷塞的","entitlements":[]}}}}}}]}"#,
        )
        .unwrap();
        assert!(plans_from_deliveries(v.get("deliveries").unwrap().as_array().unwrap()).is_empty());
    }

    #[test]
    fn empty_deliveries_means_nothing_to_claim_not_an_error() {
        // 已领过的号：deliveries 是空数组 —— 这才是真的「没有可领」
        let v: Value = serde_json::from_str(r#"{"code":0,"data":{"deliveries":[]}}"#).unwrap();
        assert!(plans_from_deliveries(&deliveries(&v)).is_empty());
        // 而没有 data 是另一回事（上面 preview_plans 里会走 Err 分支）
        let bare: Value = serde_json::from_str(r#"{"code":0,"msg":"","logid":"x"}"#).unwrap();
        assert!(bare.pointer("/data/deliveries").and_then(Value::as_array).is_none());
    }

    #[test]
    fn dedups_the_same_plan_repeated_across_banner_and_popup() {
        // 真实应答里同一个 zcode_plan 在 banner 和 success_popup 各挂了一份，不能显示两遍
        let v: Value = serde_json::from_str(
            r#"{"deliveries":[{"banner":{
                "buttons":[{"action":{"type":"claim_zcode_plan","args":{"plan_id":"p-1"}}}],
                "background":{"bundle":{"args":{"zcode_plan":{"plan_id":"p-1","name":"同一档","entitlements":[]}}}},
                "success_popup":{"buttons":[{"action":{"type":"claim_zcode_plan","args":{"plan_id":"p-1"}}}],
                  "hero":{"bundle":{"args":{"zcode_plan":{"plan_id":"p-1","name":"同一档","entitlements":[]}}}}}}}]}"#,
        )
        .unwrap();
        let plans = plans_from_deliveries(v.get("deliveries").unwrap().as_array().unwrap());
        assert_eq!(plans.len(), 1, "同一档只该出现一次，实得 {:?}", plans);
    }
}

