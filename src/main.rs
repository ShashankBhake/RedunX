use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::env;
use std::error::Error;

async fn get_analysis_id(input_url: &str) -> Result<String, Box<dyn Error>> {
    let url = "https://www.virustotal.com/api/v3/urls";
    let api_key = env::var("API_KEY").expect("API_KEY must be set");

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert("x-apikey", HeaderValue::from_str(&api_key)?);

    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .headers(headers)
        .body(format!("url={}", input_url))
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&response)?;
    // println!("{}", json);
    // println!("id: {}", json["data"]["id"]);
    if let Some(id) = json["data"]["id"].as_str() {
        let re = Regex::new(r"u-([a-f0-9]{64})-").unwrap();
        if let Some(captures) = re.captures(id) {
            if let Some(hex_part) = captures.get(1) {
                return Ok(hex_part.as_str().to_string());
            }
        }
    }
    Err("64-character hexadecimal part not found".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let api_key = env::var("API_KEY").expect("API_KEY must be set");
    println!("Enter the URL to check:");
    let mut input_url = String::new();
    std::io::stdin().read_line(&mut input_url)?;
    let input_url = input_url.trim();
    let analysis_id = get_analysis_id(input_url).await?;
    println!("Analysis ID: {}", analysis_id);
    println!("Fetching analysis result...");

    let url = format!("https://www.virustotal.com/api/v3/urls/{}", analysis_id);

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert("x-apikey", HeaderValue::from_str(&api_key)?);

    let client = reqwest::Client::new();
    let max_retries = 20;
    let mut retries = 0;

    loop {
        let response = client
            .get(&url)
            .headers(headers.clone())
            .send()
            .await?
            .text()
            .await?;

        let json: Value = serde_json::from_str(&response)?;
        if let Some(file_info) = json["meta"]["file_info"].as_object() {
            if let Some(sha256) = file_info.get("sha256") {
                println!("sha256: {}", sha256);
                break;
            } else {
                println!("sha256 not found");
            }
        } else if let Some(file_info) = json["data"]["attributes"].as_object() {
            if let Some(sha256) = file_info.get("last_http_response_content_sha256") {
                println!("sha256: {}", sha256);
                break;
            } else {
                println!("sha256 not found");
            }
        } else {
            println!("file_info not found");
            print!("{}", json);
        }

        retries += 1;
        if retries >= max_retries {
            println!("Max retries reached. Exiting...");
            break;
        }

        println!("Retrying... ({}/{})", retries, max_retries);
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }

    Ok(())
}
