use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    session_token: String,
    user_id: i64,
}

#[derive(Deserialize)]
struct ReportRequest {
    report_name: String,
    url: String,
}

#[derive(Serialize)]
struct ReportResponse {
    status: String,
    file_path: String,
}

#[derive(Serialize)]
struct UserProfile {
    id: i64,
    email: String,
    display_name: String,
}

struct AppState {
    db: PgPool,
}

// Health endpoint (clean — no vulnerabilities).
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "report-service",
    }))
}

// @vuln R1: SQL injection via `format!` macro.
// The user-supplied `email` field is interpolated directly into a raw
// SQL query string.  Rust's memory safety does not prevent SQL
// injection — an attacker can supply `' OR '1'='1' --` to bypass
// authentication and retrieve arbitrary rows.
async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> impl Responder {
    let query = format!(
        "SELECT id, email, display_name FROM users \
         WHERE email = '{}' AND password_hash = crypt('{}', password_hash)",
        body.email, body.password
    );

    let row = match sqlx::query_as::<_, (i64, String, String)>(&query)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "invalid credentials"}));
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };

    let token = generate_session_token();

    HttpResponse::Ok().json(LoginResponse {
        session_token: token,
        user_id: row.0,
    })
}

// @vuln R3: Weak RNG seeded from system clock.
// `StdRng::seed_from_u64` with a timestamp produces predictable
// output — if an attacker knows (or brute-forces) the server's clock
// at login time, they can reproduce every session token generated in
// that second.  Use `OsRng` for cryptographic randomness instead.
fn generate_session_token() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock went backwards")
        .as_secs();

    let mut rng = StdRng::seed_from_u64(timestamp);
    let token: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(token)
}

// @vuln R2: Command injection in report generation.
// The user-supplied `report_name` is interpolated directly into a
// shell command string via `format!`.  An attacker can inject shell
// metacharacters (e.g., `; rm -rf /`) to execute arbitrary commands.
async fn generate_report(body: web::Json<ReportRequest>) -> impl Responder {
    let output_path = format!("/tmp/reports/{}.pdf", body.report_name);

    let cmd = format!(
        "wkhtmltopdf --quiet {} {}",
        body.url, output_path
    );

    let result = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

    match result {
        Ok(output) if output.status.success() => {
            HttpResponse::Ok().json(ReportResponse {
                status: "completed".to_string(),
                file_path: output_path,
            })
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "report generation failed",
                "details": stderr.to_string(),
            }))
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "failed to execute command",
                "details": e.to_string(),
            }))
        }
    }
}

// Fetch user profile (clean — uses parameterised query).
async fn get_profile(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    let user_id = path.into_inner();

    let result = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT id, email, display_name FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => HttpResponse::Ok().json(UserProfile {
            id: row.0,
            email: row.1,
            display_name: row.2,
        }),
        Ok(None) => {
            HttpResponse::NotFound()
                .json(serde_json::json!({"error": "user not found"}))
        }
        Err(_) => {
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to database");

    let state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/login", web::post().to(login))
            .route("/reports", web::post().to(generate_report))
            .route("/users/{id}", web::get().to(get_profile))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
