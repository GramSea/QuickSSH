use std::env;

use qssh::{server_parser, display_servers, connect_to_server};

fn main() {
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    let servers = server_parser();

    display_servers(&servers, args.clone());

    let mut line = String::new();
    println!("Enter server number");
    std::io::stdin().read_line(&mut line).unwrap();
    let user_input = line.lines().next().unwrap();

    let server_val = user_input.parse::<u32>().unwrap() as usize;

    let chosen_server = &servers[server_val];

    connect_to_server(chosen_server, args);

    println!("QSSH Exit Success")
}
