use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;

#[derive(Debug)]
pub struct Server {
    pub index: usize,
    pub alias: String,
    pub hostname: String,
    pub args: Vec<String>,
}

impl Server {
    pub fn display_as_styled(&self, position: usize) {
        println!("{}) {}", position, self.alias)
    }
    pub fn display_as_alias(&self) {
        let args_string = self.args.join(" ");
        println!("alias {}='{} {}'", self.alias, self.hostname, args_string)
    }
}

//Used to remove the ' or " in a bash alias
fn rm_first_last_char(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next();
    chars.next_back();
    chars.as_str()
}

pub fn server_parser() -> Vec<Server> {
    let home_path = match home::home_dir() {
        Some(path) => path,
        None => panic!("Unable to get home directory")
    };
    let rc_files = vec![".zshrc", ".bashrc", ".bash_profile", ".zshenv"];
    let mut servers: Vec<Server> = Vec::new();

    for rc_file in rc_files {
        let cfg_path = [home_path.to_str().unwrap(), rc_file].join("/");

        let file = File::open(cfg_path);
        if file.is_ok() {
            let reader = BufReader::new(file.unwrap());
            let mut server_index = 1;

            for (_index, line) in reader.lines().enumerate() {
                let line = line.unwrap();
                if line.contains("alias") && line.contains("ssh") && line.contains("@") && !line.starts_with("#") {
                    let v: Vec<&str> = line.split("=").collect();
                    let alias = v[0].strip_prefix("alias").unwrap().trim().to_string();
                    let no_quotes: &str = rm_first_last_char(v[1]);
                    let mut args_vec: Vec<String> = no_quotes.split(" ").map(|s| s.to_string()).collect();
                    args_vec.retain(|x| x != "ssh");
                    let hostname_index = args_vec.iter().position(|x| x.contains("@")).unwrap();
                    let hostname = args_vec.remove(hostname_index);
                    let server = Server {
                        index: server_index,
                        alias,
                        hostname,
                        args: args_vec,
                    };
                    if servers.iter().find(|x|x.alias == server.alias).is_none() {
                        servers.push(server);
                        server_index += 1;
                    }
                }
            }
        }
    }
    servers
}

pub fn display_servers(servers: &Vec<Server>, args: Vec<String>) {
    let mut index = 0;
    for server in servers {
        // println!("{}) {}", server.index, server.alias);
        if args.iter().any(|x| x.contains("al")) {
            server.display_as_alias()
        } else {
            server.display_as_styled(index)
        }
        index += 1;
    }
}

pub fn connect_to_server(server: &Server, verbose_check: Option<usize>){
    let mut ssh_cmd = Command::new("ssh");
    ssh_cmd.arg(server.hostname.to_string());
    ssh_cmd.args(server.args.clone());
    if verbose_check.is_some(){
        ssh_cmd.arg("-vvv");
    }
    ssh_cmd.status().expect("process failed to execute");
}