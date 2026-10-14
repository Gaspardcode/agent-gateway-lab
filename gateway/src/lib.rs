pub mod audit;
pub mod policy;
pub mod ratelimit;
pub mod tls;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use audit::AuditEvent;
use policy::{Mode, Policy};
use ratelimit::RateLimiter;

pub struct AppState {
    pub policy: Policy,
    pub http: reqwest::Client,
    pub limiter: RateLimiter,
}

/// CN du certificat client, injecté par connexion TLS.
#[derive(Clone)]
pub struct ClientId(pub Option<String>);

pub fn router(state: Arc<AppState>) -> Router {
    let max = state.policy.max_body_bytes;
    Router::new()
        .route("/v1/chat/completions", post(chat))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(max))
        .with_state(state)
}

/// Boucle d'acceptation TLS : axum::serve ne gère pas le mTLS.
pub async fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor, app: Router) -> anyhow::Result<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    // Sans certificat valide, la poignée de main échoue : c'est un échec d'authentification.
                    println!(
                        "{}",
                        json!({"event": "tls_handshake_failed", "auth_fail": true,
                               "peer": peer.to_string(), "error": e.to_string()})
                    );
                    return;
                }
                Err(_) => return,
            };
            let cn = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(tls::common_name);
            let svc = TowerToHyperService::new(app.layer(Extension(ClientId(cn))));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn chat(
    State(st): State<Arc<AppState>>,
    Extension(ClientId(cn)): Extension<ClientId>,
    body: Bytes,
) -> Response {
    let t0 = Instant::now();
    let mut ev = AuditEvent::new(uuid::Uuid::new_v4().to_string(), cn.clone(), st.policy.mode);
    let mut resp = process(&st, cn.as_deref(), &body, &mut ev).await;
    ev.status = resp.status().as_u16();
    ev.latency_ms = t0.elapsed().as_millis();
    ev.emit();
    if let Ok(v) = ev.request_id.parse() {
        resp.headers_mut().insert("x-request-id", v);
    }
    if let Ok(v) = ev.decision.parse() {
        resp.headers_mut().insert("x-gateway-decision", v);
    }
    resp
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"error": {"message": msg, "type": "gateway"}}))).into_response()
}

async fn process(st: &AppState, cn: Option<&str>, body: &[u8], ev: &mut AuditEvent) -> Response {
    let Some(name) = cn else {
        ev.auth_fail = true;
        ev.decision = "deny";
        return error(StatusCode::UNAUTHORIZED, "certificat client requis");
    };
    let Some(client) = st.policy.clients.get(name) else {
        ev.auth_fail = true;
        ev.decision = "deny";
        return error(StatusCode::FORBIDDEN, "client inconnu de la politique");
    };
    if !st.limiter.check(name, client.rate_per_minute) {
        ev.rate_limited = true;
        ev.decision = "deny";
        return error(StatusCode::TOO_MANY_REQUESTS, "limite de débit atteinte");
    }
    let Ok(req) = serde_json::from_slice::<Value>(body) else {
        ev.decision = "deny";
        return error(StatusCode::BAD_REQUEST, "JSON invalide");
    };
    if req.get("stream").and_then(Value::as_bool) == Some(true) {
        ev.decision = "deny";
        return error(StatusCode::BAD_REQUEST, "stream non supporté : la réponse doit être inspectée en entier");
    }

    ev.mode = st.policy.mode_for(client);
    let enforce = ev.mode == Mode::Enforce;
    let rv = st.policy.check_request(client, &req);
    ev.tainted = rv.tainted;
    let req_block = rv.findings.iter().any(|f| f.block);
    ev.add(rv.findings.iter().cloned());
    if req_block {
        if enforce {
            ev.decision = "block";
            return error(StatusCode::FORBIDDEN, &format!("refusé par la politique : {}", ev.rules.join(", ")));
        }
        ev.decision = "would_block";
    }

    let up_t0 = Instant::now();
    let up = st
        .http
        .post(format!("{}/v1/chat/completions", st.policy.upstream))
        .json(&req)
        .send()
        .await;
    ev.upstream_ms = Some(up_t0.elapsed().as_millis());
    let up = match up {
        Ok(r) => r,
        Err(e) => {
            ev.decision = "error";
            eprintln!("upstream: {e}");
            return error(StatusCode::BAD_GATEWAY, "modèle injoignable");
        }
    };
    let status = up.status();
    let Ok(mut resp) = up.json::<Value>().await else {
        ev.decision = "error";
        return error(StatusCode::BAD_GATEWAY, "réponse du modèle illisible");
    };
    if !status.is_success() {
        ev.decision = "error";
        let code = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        return (code, Json(resp)).into_response();
    }
    ev.prompt_tokens = resp.pointer("/usage/prompt_tokens").and_then(Value::as_u64);
    ev.completion_tokens = resp.pointer("/usage/completion_tokens").and_then(Value::as_u64);

    let vr = st.policy.check_response(client, &rv, &resp);
    ev.tools_called = vr.tools_called.clone();
    let blocked: Vec<&'static str> = vr.findings.iter().filter(|f| f.block).map(|f| f.rule).collect();
    ev.add(vr.findings);
    if !blocked.is_empty() {
        if enforce {
            let tool_block = blocked.iter().any(|r| *r != "markdown_exfil");
            ev.decision = if tool_block { "block" } else { "redact" };
            rewrite(&st.policy, &mut resp, tool_block, &blocked);
        } else if ev.decision == "allow" {
            ev.decision = "would_block";
        }
    }
    (StatusCode::OK, Json(resp)).into_response()
}

/// Retire les appels d'outils refusés et les liens d'exfiltration, en gardant
/// une réponse valide au format OpenAI pour que l'agent continue proprement.
fn rewrite(policy: &Policy, resp: &mut Value, tool_block: bool, rules: &[&str]) {
    let Some(choices) = resp.get_mut("choices").and_then(Value::as_array_mut) else { return };
    for choice in choices {
        let Some(msg) = choice.get_mut("message").and_then(Value::as_object_mut) else { continue };
        if tool_block {
            msg.remove("tool_calls");
            msg.insert(
                "content".into(),
                json!(format!(
                    "Action refusée par la passerelle de sécurité ({}). Explique à l'utilisateur que \
                     cette action n'est pas autorisée, sans la retenter.",
                    rules.join(", ")
                )),
            );
            choice["finish_reason"] = json!("stop");
        } else if let Some(Value::String(c)) = msg.get("content") {
            let red = policy.redact_markdown(c);
            msg.insert("content".into(), json!(red));
        }
    }
}
