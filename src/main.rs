// src/main.rs
use env_logger;
use log::info;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::error::Error;
use std::fmt;
use warp::reject::Reject;
use warp::Filter;

#[derive(Deserialize)]
struct UrlQuery {
    url: String,
}

// Custom error type
#[derive(Debug)]
struct CustomError {
    message: String,
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for CustomError {}

impl Reject for CustomError {}

async fn get_analysis_id(input_url: &str) -> Result<String, warp::Rejection> {
    let url = "https://www.virustotal.com/api/v3/urls";
    let api_key = env::var("API_KEY").map_err(|e| {
        warp::reject::custom(CustomError {
            message: e.to_string(),
        })
    })?;

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(
        "x-apikey",
        HeaderValue::from_str(&api_key).map_err(|e| {
            warp::reject::custom(CustomError {
                message: e.to_string(),
            })
        })?,
    );

    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .headers(headers)
        .body(format!("url={}", input_url))
        .send()
        .await
        .map_err(|e| {
            warp::reject::custom(CustomError {
                message: e.to_string(),
            })
        })?
        .text()
        .await
        .map_err(|e| {
            warp::reject::custom(CustomError {
                message: e.to_string(),
            })
        })?;

    let json: Value = serde_json::from_str(&response).map_err(|e| {
        warp::reject::custom(CustomError {
            message: e.to_string(),
        })
    })?;
    if let Some(id) = json["data"]["id"].as_str() {
        let re = Regex::new(r"u-([a-f0-9]{64})-").unwrap();
        if let Some(captures) = re.captures(id) {
            if let Some(hex_part) = captures.get(1) {
                return Ok(hex_part.as_str().to_string());
            }
        }
    }
    Err(warp::reject::custom(CustomError {
        message: "64-character hexadecimal part not found".to_string(),
    }))
}

async fn fetch_analysis_result(analysis_id: &str) -> Result<String, warp::Rejection> {
    let api_key = env::var("API_KEY").map_err(|e| {
        warp::reject::custom(CustomError {
            message: e.to_string(),
        })
    })?;
    let url = format!("https://www.virustotal.com/api/v3/urls/{}", analysis_id);

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        "x-apikey",
        HeaderValue::from_str(&api_key).map_err(|e| {
            warp::reject::custom(CustomError {
                message: e.to_string(),
            })
        })?,
    );

    let client = reqwest::Client::new();
    let max_retries = 20;
    let mut retries = 0;

    loop {
        let response = client
            .get(&url)
            .headers(headers.clone())
            .send()
            .await
            .map_err(|e| {
                warp::reject::custom(CustomError {
                    message: e.to_string(),
                })
            })?
            .text()
            .await
            .map_err(|e| {
                warp::reject::custom(CustomError {
                    message: e.to_string(),
                })
            })?;

        let json: Value = serde_json::from_str(&response).map_err(|e| {
            warp::reject::custom(CustomError {
                message: e.to_string(),
            })
        })?;
        if let Some(file_info) = json["meta"]["file_info"].as_object() {
            if let Some(sha256) = file_info.get("sha256") {
                return Ok(sha256.as_str().unwrap().to_string());
            }
        } else if let Some(file_info) = json["data"]["attributes"].as_object() {
            if let Some(sha256) = file_info.get("last_http_response_content_sha256") {
                return Ok(sha256.as_str().unwrap().to_string());
            }
        }

        retries += 1;
        if retries >= max_retries {
            return Err(warp::reject::custom(CustomError {
                message: "Max retries reached".to_string(),
            }));
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}

async fn handle_get_hash(query: UrlQuery) -> Result<impl warp::Reply, warp::Rejection> {
    let analysis_id = get_analysis_id(&query.url).await?;
    let hash = fetch_analysis_result(&analysis_id).await?;
    Ok(warp::reply::json(&hash))
}

#[tokio::main]
async fn main() {
    // Initialize the logger
    env_logger::init();
    dotenv::dotenv().ok();

    // Log server start
    info!("Starting the server...");

    let get_hash = warp::path("getHash")
        .and(warp::get())
        .and(warp::query::<UrlQuery>())
        .and_then(handle_get_hash);

    // Log server listening status
    info!("Server is running at http://127.0.0.1:3030");

    warp::serve(get_hash).run(([127, 0, 0, 1], 3030)).await;
}
