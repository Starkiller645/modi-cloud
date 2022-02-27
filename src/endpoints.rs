mod filters {
}

pub mod routes {
    //use warp::{Filter, Rejection, Reply};
    use warp::http::Response;
    use warp::filters::multipart::*;
    use warp::Buf;
    use std::fs::{File, OpenOptions, read_to_string};
    use std::io::prelude::*;
    use core::result::Result;
    use std::path::Path;
    use sha2::{Sha256, Digest};
    use data_encoding::HEXLOWER;
    //use serde_json::*;
    use crate::endpoints::models::*;
    //use crate::endpoints::filters::*;
    use crate::console::*;

    //use super::models::*;
    use std::convert::Infallible;
    use std::time::SystemTime;
    use uuid::Uuid;
    use futures::*;

    pub fn check_auth(username: &String, token: String) -> bool {
        let mut check_uname = true;
        let mut new_tokens_vector = Vec::<&str>::new();
        let original_file_data = read_to_string("logins.txt").expect("Couldn't read login file");
        for line in original_file_data.lines() {
            if line == "" {
                continue;
            }
            let line_split = line.split("@");
            let line_vec: Vec<&str> = line_split.collect();
            println!("{}", line_vec[0]);
            let auth_codes = line_vec[1].to_string();
            let auth: Vec<&str> = auth_codes.split(":").collect();

            let file_timestamp: u64 = auth[0].parse().expect("File timestamp error");
            let file_token = auth[1].to_string();

            let current_time: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Failed to get system time.").as_secs();
            let time_elapsed: u64 = current_time - file_timestamp as u64;
            if time_elapsed >= 3600 {
                log(&format!("Token {} is out of date, deleting...", file_token), Endpoints::Auth);
                continue;
            } else {
                new_tokens_vector.push(line);
            }


        }

        let mut login_file = OpenOptions::new().write(true).append(false).open("logins.txt").expect("Couldn't open login file");
        for line in &new_tokens_vector {
            login_file.write(&format!("{}\n", line).as_bytes()).expect("Couldn't write to login file");
        }
    
        if username == "" {
            log("Using token-only authentication, no user found", Endpoints::Login);
            check_uname = false;
        }
        log(&format!("Checking authentication for user {} with token {}", username, token).to_string(), Endpoints::Auth);
        let file_data = read_to_string("logins.txt").expect("Couldn't read file");
        let mut user_in = false;
        let mut valid_token = false;
        for line in file_data.lines() {
            if line.len() <= 0 {
                continue;
            }

            let file_uname: String;
            let file_timestamp: u32;
            let file_token: String;

            let line_split = line.split("@");
            let line_vec: Vec<&str> = line_split.collect();
            let auth_codes = line_vec[1].to_string();
            let auth: Vec<&str> = auth_codes.split(":").collect();

            file_uname = line_vec[0].to_string();
            file_timestamp = auth[0].parse().expect("File timestamp error");
            file_token = auth[1].to_string();

            let current_time: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Failed to get system time.").as_secs();
            let time_elapsed: u64 = current_time - file_timestamp as u64;
            if time_elapsed >= 3600 {
                log(&format!("Token {} is out of date, deleting...", file_token), Endpoints::Auth);
                continue;
            } else {
                new_tokens_vector.push(line);
            }

            log(&format!("Authorization token: {}", file_token), Endpoints::Auth);
            log(&format!("Username: {}", file_uname), Endpoints::Auth);
            log(&format!("Timestamp: {}", file_timestamp.to_string()), Endpoints::Auth);

            if line_vec[0] == username {
                log("Found user", Endpoints::Auth);
                user_in = true;
                let token_vec: Vec<&str> = line.split(":").collect();
                if token_vec[1] == token {
                    log(&format!("{}", token_vec[1]).to_string(), Endpoints::Auth);
                    log("API Token matches!", Endpoints::Auth);
                    valid_token = true;
                }
            }
        }
        if valid_token && !check_uname {
            return true;
        } else if valid_token && check_uname && user_in {
            return true;
        } else {
            return false;
        }
    }

    pub async fn auth_user(username: String, password: String) -> std::result::Result<impl warp::Reply, Infallible> {
        let path = Path::new("users.json");
        let mut user_data = String::new();
        let mut file = match File::open(&path) {
            Err(reason) => panic!("Couldn't open 'users.json': {}", reason),
            Ok(file)    => file,
        };
        match file.read_to_string(&mut user_data) {
            Err(reason) => panic!("Couldn't read 'users.json': {}", reason),
            Ok(_)       => println!("Read 'users.json'")
        }

        let json: Vec<User> = match serde_json::from_str(&user_data) {
            Err(_) => panic!("Couldn't parse string"),
            Ok(json)    => json
        };
        let mut have_user = false;
        let mut user_detail = User{name: "".to_string(), password_hash: "".to_string()}; 
        for user in json {
            if user.name == username {
                user_detail = user;
                have_user = true;
            }
        }
        if !have_user {
            let res_data = Res{response: 401, message: "Could not find user"};
            let res = match serde_json::to_string(&res_data) {
                Err(_) => panic!("Error while encoding JSON object to String"),
                Ok(res)       => res,
            };
            Ok(Response::builder()
                .status(res_data.response)
                .body(
                    res,
                )
            )

        } else {
            let mut hash = Sha256::new();
            hash.update(password);
            let result = hash.finalize();
            let pwd_hash = HEXLOWER.encode(result.as_ref());
            if pwd_hash == user_detail.password_hash {

                let mut auth_code: String = "".to_owned();
                
                let time: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Failed to get system time").as_secs();
                let time_now: &String = &time.to_string().to_owned();
                auth_code.push_str(time_now);
                auth_code.push_str(&";".to_owned());
                auth_code.push_str(&username);
                log(&auth_code, Endpoints::Login);

                let mut hash_code = Sha256::new();
                hash_code.update(auth_code);
                let auth_dgst = hash_code.finalize();
                let final_auth_code = HEXLOWER.encode(auth_dgst.as_ref());

                let mut file = OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open("logins.txt")
                    .unwrap();
                let id: &String = &format!("{}@{}:{}", &username, time_now, &final_auth_code);
                write!(file, "{}\n", id.to_string()).expect("Could not write to file");


                log(&format!("Auth code {} registered for user {}", &final_auth_code, username).to_string(), Endpoints::Login);

                let res_data = AuthRes{response: 200, message: "Authentication Succeeded", auth_code: &final_auth_code};
                let res = match serde_json::to_string(&res_data) {
                    Err(_) => panic!("Error while encoding JSON object to String"),
                    Ok(res)       => res,
                };
                Ok(Response::builder()
                   .status(res_data.response)
                   .body(
                        res,
                    )
                )
            } else {
                let res_data = Res{response: 401, message: "Incorrect password"};
                let res = match serde_json::to_string(&res_data) {
                    Err(_) => panic!("Error while encoding JSON object to String"),
                    Ok(res)       => res,
                };
                Ok(Response::builder()
                    .status(res_data.response)
                    .body(
                        res,
                    )
                )
            }
        }

    }

    pub async fn try_auth(user: String, token: String) -> Result<impl warp::Reply, Infallible> {
        let auth_check = check_auth(&user, token);
        if auth_check {
            log("Auth check succeeded", Endpoints::Login);
        } else {
            log("Auth check failed", Endpoints::Login);
        }
        let mut status = 401;
        let mut res = Res{response: status, message: "Invalid authentication token"};
        if auth_check {
            status = 200;
            res.response = status;
            res.message = "Authentication bearer token OK!";
        }
        let res_data = match serde_json::to_string(&res) {
            Err(_)       => panic!("Error while encoding JSON object to String"),
            Ok(res_data) => res_data
        };
        Ok(Response::builder()
           .status(status)
           .body(res_data)
        )
    }

    pub async fn upload_pkg(pkg_name: String, user: String, token: String, form: FormData) -> Result<impl warp::Reply, warp::Rejection> {
        log(&format!("Receiving new package upload '{}'", pkg_name), Endpoints::Upload);

        let parts: Vec<Part> = form.try_collect().await.map_err(|e| {
            log(&format!("Form error: {}", e), Endpoints::Upload);
            warp::reject::reject();
        }).expect("Failed");

        if !check_auth(&user, token) {
            log("Authentication failed, rejecting...", Endpoints::Upload);
            warp::reject::reject();
		    let status = 401;
		    let res = Res{response: status, message: "Invalid authentication token"};
			let res_data = match serde_json::to_string(&res) {
                Err(_)       => panic!("Error while encoding JSON object to String"),
                Ok(res_data) => res_data
            };

            return Ok(Response::builder()
               .status(status)
               .body(res_data))
        }
        
        let package_registry = read_to_string("registry.json").expect("Couldn't find registry file...");
        let mut pkg_id: String = "".to_string();
        let json_registry: Vec<Package> = serde_json::from_str(&package_registry).expect("Invalid JSON in registry file");
        let mut new_registry = Vec::new();

        for pkg in json_registry {
            if pkg.name != pkg_name {
                new_registry.push(pkg);
            } else {
                pkg_id = pkg.id.to_string();
            }
        }
        
        if pkg_id == "" {
            let pkg_uuid = Uuid::new_v4();
            pkg_id = pkg_uuid.to_string();
        }

        let mut byte_vector = Vec::<u8>::new();

        for mut part in parts {
            if part.name() == "file" {
                log("Found file in form data", Endpoints::Upload);
                part.data().map(|data| {
                    let mut buffer = data.unwrap().expect("");
                    while buffer.has_remaining() {
                        byte_vector.push(buffer.get_u8());
                    }
                }).await;
            }
        }

        let pkg_file = format!("store/{}.{}", pkg_name, "modi.pkg");

        let new_pkg = Package{name: pkg_name, id: pkg_id.to_string(), file: pkg_file.to_string(), submitter: user};

        log(&new_pkg.name, Endpoints::Upload);
        log(&new_pkg.id, Endpoints::Upload);
        log(&new_pkg.file, Endpoints::Upload);
        log(&new_pkg.submitter, Endpoints::Upload);

        new_registry.push(new_pkg);

        let registry_data = serde_json::json!(new_registry);
        log(&registry_data.to_string(), Endpoints::Upload);

        let mut reg_file = File::create("registry.json").expect("Couldn't open registry file");
        reg_file.write_all(&serde_json::to_string_pretty(&registry_data).expect("Error converting JSON to String").into_bytes()).expect("Couldn't write to registry file");

        let mut pkg_file = File::create(pkg_file).expect("Couldn't open package file for writing");
        pkg_file.write_all(&byte_vector).expect("Failed writing byte-array to package file");

        Ok(Response::builder()
           .status(200)
           .body("".to_string())
        )
    }

    pub async fn get_pkg(pkg_name: String) -> Result<impl warp::Reply, Infallible> {
        let mut byte_array = Vec::<u8>::new();


        let package_registry = read_to_string("registry.json").expect("Couldn't find registry file...");
        let json_registry: Vec<Package> = serde_json::from_str(&package_registry).expect("Invalid JSON in registry file");

        let mut have_pkg = false;
        let mut pkg_struct = Package{name: "".to_string(), id: "".to_string(), submitter: "".to_string(), file: "".to_string()};
        for pkg in json_registry {
            if pkg.name == pkg_name {
                have_pkg = true;
                pkg_struct = pkg;
            }
        }

        if have_pkg {
			let mut pkg_file = File::open(pkg_struct.file).expect("Couldn't read package file");
			pkg_file.read_to_end(&mut byte_array).expect("Couldn't read file");
            Ok(Response::builder()
                .status(200)
                .header("X-Modi-Package-Name", pkg_struct.name)
                .header("X-Modi-Package-Submitter", pkg_struct.submitter)
                .body(byte_array)
        ) } else {
            Ok(Response::builder().status(404).body(byte_array))
        }
    }
}
 
mod models {
    use serde::{Deserialize, Serialize};

//    #[derive(Serialize, Deserialize)]
//    pub struct UserData<'b> {
//        data: &'b Vec<User>
//    }

    #[derive(Serialize, Deserialize)]
    pub struct Package {
        pub name: String,
        pub id: String,
        pub file: String,
        pub submitter: String
    }

    #[derive(Serialize, Deserialize)]
    pub struct Res<'c> {
        pub response: u16,
        pub message: &'c str
    }

    #[derive(Serialize, Deserialize)]
    pub struct AuthRes<'d> {
        pub response: u16,
        pub message: &'d str,
        pub auth_code: &'d str
    }

    #[derive(Serialize, Deserialize)]
    pub struct User {
        pub name: String,
        pub password_hash: String
    }
}
