use std::{env, fs};
use std::collections::VecDeque;

use qssh::{Server, server_parser, display_servers, connect_to_server};

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let servers = server_parser();
    let verbose_check = args.iter().position(|x| x=="-vvv");

    display_servers(&servers, args);

    let mut line = String::new();
    println!("Enter server number");
    std::io::stdin().read_line(&mut line).unwrap();
    let user_input = line.lines().next().unwrap();

    let server_val = user_input.parse::<u32>().unwrap() as usize;

    let chosen_server = &servers[server_val];

    connect_to_server(chosen_server, verbose_check);

    println!("Program Complete")
}
