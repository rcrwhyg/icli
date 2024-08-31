use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::fs::read_dir;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct FileInfo {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    sub_files: Vec<FileInfo>,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on port {}", path, addr);

    let state = HttpServeState { path: path.clone() };

    // axum router
    let router = Router::new()
        .route("/*path", get(file_handler))
        .nest_service("/tower", ServeDir::new(path))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, router).await?;

    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    let p: PathBuf = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        if !p.ends_with("index.html") {
            return (
                StatusCode::NOT_FOUND,
                format!("File {} not Found", p.display()),
            );
        }

        let dir = p.parent().unwrap();
        println!("Directory {:?}", dir);
        // std::path::Path::new(&state.path).join("index.html");
        let files: Vec<FileInfo> = match process_directory_index(dir).await {
            Ok(files) => files,
            Err(err) => {
                warn!("Error reading directory: {}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error reading directory: {}", err),
                );
            }
        };

        let mut ret = String::new();
        ret.push_str("<ul>");
        for file in files {
            println!("{}", json!(file));
            if file.is_dir {
                ret.push_str(
                    format!(
                        "<li><a href=\"{}/index.html\">{}</a></li>",
                        file.path, file.name
                    )
                    .as_str(),
                );
            } else {
                ret.push_str(
                    format!("<li><a href=\"{}\">{}</a></li>", file.path, file.name).as_str(),
                );
            }
        }
        ret.push_str("</ul>");

        (
            StatusCode::OK,
            format!("<html><body> {} </body></html>", ret),
        )
    } else {
        // TODO: test p is a directory
        // if it is a directory, list all files/subdirectories as
        // <li><a href="/path/to/file">file name</a></li>
        // <html><body><ul>...</ul></body></html>
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, content)
            }
            Err(err) => {
                warn!("Error reading file: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
        }
    }
}

async fn process_directory_index(path: &std::path::Path) -> anyhow::Result<Vec<FileInfo>> {
    let mut files = Vec::new();

    let mut dir = match read_dir(path).await {
        Ok(dir) => dir,
        Err(err) => {
            warn!("Error reading directory: {}", err);
            return Err(err.into());
        }
    };

    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;
        let file_type = metadata.file_type();

        // let mut file = FileInfo {
        let file = FileInfo {
            name: entry.file_name().into_string().unwrap(),
            path: path
                .iter()
                .skip(1)
                .map(|p| p.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
            is_dir: file_type.is_dir(),
            size: metadata.len(),
            sub_files: Vec::new(),
        };

        // 递归展开所有子目录
        // if file_type.is_dir() {
        //     let sub_files = Box::pin(process_directory_index(&path)).await?;
        //     file.sub_files.extend(sub_files);
        // }

        files.push(file);
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package]"));
    }
}
