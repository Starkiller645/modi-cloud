use colored::*;

pub enum Endpoints {
    Upload,
    Package,
    Login,
    Auth
}

struct Endpoint<'ep> {
    name: &'ep String,
    color: [u8; 3]
}

pub fn log<'log> (message: &str, endpoint: Endpoints) {
    use Endpoints::*;
    let hello_name = &String::from("upload");
    let world_name = &String::from("package");
    let login_name = &String::from("login");
    let auth_name = &String::from("auth");
    let ep = match endpoint {
        Upload => Endpoint{color: [255, 175, 215], name: hello_name},
        Package => Endpoint{color: [175, 215, 255], name: world_name},
        Login => Endpoint{color: [135, 255, 175], name: login_name},
        Auth  => Endpoint{color: [255, 215, 0], name: auth_name}
    };
    
    print!("[{}] {}\n", ep.name.truecolor(ep.color[0], ep.color[1], ep.color[2]).bold(), message);
}

