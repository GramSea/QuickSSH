use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;

#[derive(Debug)]
pub struct Server {
    pub index: usize,
    pub alias: String,
    // All fields from the ssh config
    pub host: String,
    pub r#match: String,
    pub address_family: String,
    pub batch_mode: String,
    pub bind_address: String,
    pub challenge_response_authentication: String,
    pub check_host_ip: String,
    pub cipher: String,
    pub ciphers: String,
    pub clear_all_forwardings: String,
    pub compression: String,
    pub compression_level: String,
    pub connection_attempts: String,
    pub connect_timeout: String,
    pub control_master: String,
    pub control_path: String,
    pub dynamic_forward: String,
    pub enable_sshkeysign: String,
    pub escape_char: String,
    pub exit_on_forward_failure: String,
    pub forward_agent: String,
    pub forward_x11: String,
    pub forward_x11_trusted: String,
    pub gateway_ports: String,
    pub global_known_hosts_file: String,
    pub gssapi_authentication: String,
    pub gssapi_key_exchange: String,
    pub gssapi_client_identity: String,
    pub gssapi_delegate_credentials: String,
    pub gssapi_renewal_forces_rekey: String,
    pub gssapi_trust_dns: String,
    pub hash_known_hosts: String,
    pub hostbased_authentication: String,
    pub host_key_algorithms: String,
    pub host_key_alias: String,
    pub host_name: String,
    pub identities_only: String,
    pub identity_file: String,
    pub kbd_interactive_authentication: String,
    pub kbd_interactive_devices: String,
    pub local_command: String,
    pub local_forward: String,
    pub log_level: String,
    pub macs: String,
    pub no_host_authentication_for_localhost: String,
    pub number_of_password_prompts: String,
    pub password_authentication: String,
    pub permit_local_command: String,
    pub port: String,
    pub preferred_authentications: String,
    pub protocol: String,
    pub proxy_command: String,
    pub pubkey_authentication: String,
    pub rekey_limit: String,
    pub remote_forward: String,
    pub rhosts_rsa_authentication: String,
    pub rsa_authentication: String,
    pub send_env: String,
    pub server_alive_count_max: String,
    pub server_alive_interval: String,
    pub smartcard_device: String,
    pub strict_host_key_checking: String,
    pub tcpkeep_alive: String,
    pub tunnel: String,
    pub tunnel_device: String,
    pub user: String,
    pub use_privileged_port: String,
    pub user_known_hosts_file: String,
    pub verify_host_key_dns: String,
    pub visual_host_key: String,
    // Args for bashrc style alias
    pub xauth_location: String,
    pub args: Vec<String>,
}

impl Server {
    pub fn display_as_styled(&self, position: usize) {
        println!("{}) {}", position, self.alias)
    }
    pub fn display_as_alias(&self) {
        if !self.args.is_empty() {
            let args_string = self.args.join(" ");
            println!("alias {}='ssh {} {}'", self.alias, self.host_name, args_string)
        }
    }
    pub fn display_server_info(&self) {
        println!();
        if self.alias != "" { println!("Host {}", self.alias) }
        if self.address_family != "" { println!("\t{}", self.address_family) }
        if self.batch_mode != "" { println!("\t{}", self.batch_mode) }
        if self.bind_address != "" { println!("\t{}", self.bind_address) }
        if self.challenge_response_authentication != "" { println!("\t{}", self.challenge_response_authentication) }
        if self.check_host_ip != "" { println!("\t{}", self.check_host_ip) }
        if self.cipher != "" { println!("\t{}", self.cipher) }
        if self.ciphers != "" { println!("\t{}", self.ciphers) }
        if self.clear_all_forwardings != "" { println!("\t{}", self.clear_all_forwardings) }
        if self.compression != "" { println!("\t{}", self.compression) }
        if self.compression_level != "" { println!("\t{}", self.compression_level) }
        if self.connection_attempts != "" { println!("\t{}", self.connection_attempts) }
        if self.connect_timeout != "" { println!("\t{}", self.connect_timeout) }
        if self.control_master != "" { println!("\t{}", self.control_master) }
        if self.control_path != "" { println!("\t{}", self.control_path) }
        if self.dynamic_forward != "" { println!("\t{}", self.dynamic_forward) }
        if self.enable_sshkeysign != "" { println!("\t{}", self.enable_sshkeysign) }
        if self.escape_char != "" { println!("\t{}", self.escape_char) }
        if self.exit_on_forward_failure != "" { println!("\t{}", self.exit_on_forward_failure) }
        if self.forward_agent != "" { println!("\t{}", self.forward_agent) }
        if self.forward_x11 != "" { println!("\t{}", self.forward_x11) }
        if self.forward_x11_trusted != "" { println!("\t{}", self.forward_x11_trusted) }
        if self.gateway_ports != "" { println!("\t{}", self.gateway_ports) }
        if self.global_known_hosts_file != "" { println!("\t{}", self.global_known_hosts_file) }
        if self.gssapi_authentication != "" { println!("\t{}", self.gssapi_authentication) }
        if self.gssapi_key_exchange != "" { println!("\t{}", self.gssapi_key_exchange) }
        if self.gssapi_client_identity != "" { println!("\t{}", self.gssapi_client_identity) }
        if self.gssapi_delegate_credentials != "" { println!("\t{}", self.gssapi_delegate_credentials) }
        if self.gssapi_renewal_forces_rekey != "" { println!("\t{}", self.gssapi_renewal_forces_rekey) }
        if self.gssapi_trust_dns != "" { println!("\t{}", self.gssapi_trust_dns) }
        if self.hash_known_hosts != "" { println!("\t{}", self.hash_known_hosts) }
        if self.hostbased_authentication != "" { println!("\t{}", self.hostbased_authentication) }
        if self.host_key_algorithms != "" { println!("\t{}", self.host_key_algorithms) }
        if self.host_key_alias != "" { println!("\t{}", self.host_key_alias) }
        if self.host_name != ""  { println!("\t{}", self.host_name) }
        if self.identities_only != "" { println!("\t{}", self.identities_only) }
        if self.identity_file != "" { println!("\t{}", self.identity_file) }
        if self.kbd_interactive_authentication != "" { println!("\t{}", self.kbd_interactive_authentication) }
        if self.kbd_interactive_devices != "" { println!("\t{}", self.kbd_interactive_devices) }
        if self.local_command != "" { println!("\t{}", self.local_command) }
        if self.local_forward != "" { println!("\t{}", self.local_forward) }
        if self.log_level != "" { println!("\t{}", self.log_level) }
        if self.macs != "" { println!("\t{}", self.macs) }
        if self.no_host_authentication_for_localhost != "" { println!("\t{}", self.no_host_authentication_for_localhost) }
        if self.number_of_password_prompts != "" { println!("\t{}", self.number_of_password_prompts) }
        if self.password_authentication != "" { println!("\t{}", self.password_authentication) }
        if self.permit_local_command != "" { println!("\t{}", self.permit_local_command) }
        if self.port != "" { println!("\t{}", self.port) }
        if self.preferred_authentications != "" { println!("\t{}", self.preferred_authentications) }
        if self.protocol != "" { println!("\t{}", self.protocol) }
        if self.proxy_command != "" { println!("\t{}", self.proxy_command) }
        if self.pubkey_authentication != "" { println!("\t{}", self.pubkey_authentication) }
        if self.rekey_limit != "" { println!("\t{}", self.rekey_limit) }
        if self.remote_forward != "" { println!("\t{}", self.remote_forward) }
        if self.rhosts_rsa_authentication != "" { println!("\t{}", self.rhosts_rsa_authentication) }
        if self.rsa_authentication != "" { println!("\t{}", self.rsa_authentication) }
        if self.send_env != "" { println!("\t{}", self.send_env) }
        if self.server_alive_count_max != "" { println!("\t{}", self.server_alive_count_max) }
        if self.server_alive_interval != "" { println!("\t{}", self.server_alive_interval) }
        if self.smartcard_device != "" { println!("\t{}", self.smartcard_device) }
        if self.strict_host_key_checking != "" { println!("\t{}", self.strict_host_key_checking) }
        if self.tcpkeep_alive != "" { println!("\t{}", self.tcpkeep_alive) }
        if self.tunnel != "" { println!("\t{}", self.tunnel) }
        if self.tunnel_device != "" { println!("\t{}", self.tunnel_device) }
        if self.use_privileged_port != "" { println!("\t{}", self.use_privileged_port) }
        if self.user != "" { println!("\t{}", self.user) }
        if self.user_known_hosts_file != "" { println!("\t{}", self.user_known_hosts_file) }
        if self.verify_host_key_dns != "" { println!("\t{}", self.verify_host_key_dns) }
        if self.visual_host_key != "" { println!("\t{}", self.visual_host_key) }
        if self.xauth_location != "" { println!("\t{}", self.xauth_location) }
        println!();
    }
}

impl Default for Server {
    fn default() -> Self {
        Server {
            index: 0,
            alias: "".to_string(),
            host: "".to_string(),
            r#match: "".to_string(),
            address_family: "".to_string(),
            batch_mode: "".to_string(),
            bind_address: "".to_string(),
            challenge_response_authentication: "".to_string(),
            check_host_ip: "".to_string(),
            cipher: "".to_string(),
            ciphers: "".to_string(),
            clear_all_forwardings: "".to_string(),
            compression: "".to_string(),
            compression_level: "".to_string(),
            connection_attempts: "".to_string(),
            connect_timeout: "".to_string(),
            control_master: "".to_string(),
            control_path: "".to_string(),
            dynamic_forward: "".to_string(),
            enable_sshkeysign: "".to_string(),
            escape_char: "".to_string(),
            exit_on_forward_failure: "".to_string(),
            forward_agent: "".to_string(),
            forward_x11: "".to_string(),
            forward_x11_trusted: "".to_string(),
            gateway_ports: "".to_string(),
            global_known_hosts_file: "".to_string(),
            gssapi_authentication: "".to_string(),
            gssapi_key_exchange: "".to_string(),
            gssapi_client_identity: "".to_string(),
            gssapi_delegate_credentials: "".to_string(),
            gssapi_renewal_forces_rekey: "".to_string(),
            gssapi_trust_dns: "".to_string(),
            hash_known_hosts: "".to_string(),
            hostbased_authentication: "".to_string(),
            host_key_algorithms: "".to_string(),
            host_key_alias: "".to_string(),
            host_name: "".to_string(),
            identities_only: "".to_string(),
            identity_file: "".to_string(),
            kbd_interactive_authentication: "".to_string(),
            kbd_interactive_devices: "".to_string(),
            local_command: "".to_string(),
            local_forward: "".to_string(),
            log_level: "".to_string(),
            macs: "".to_string(),
            no_host_authentication_for_localhost: "".to_string(),
            number_of_password_prompts: "".to_string(),
            password_authentication: "".to_string(),
            permit_local_command: "".to_string(),
            port: "".to_string(),
            preferred_authentications: "".to_string(),
            protocol: "".to_string(),
            proxy_command: "".to_string(),
            pubkey_authentication: "".to_string(),
            rekey_limit: "".to_string(),
            remote_forward: "".to_string(),
            rhosts_rsa_authentication: "".to_string(),
            rsa_authentication: "".to_string(),
            send_env: "".to_string(),
            server_alive_count_max: "".to_string(),
            server_alive_interval: "".to_string(),
            smartcard_device: "".to_string(),
            strict_host_key_checking: "".to_string(),
            tcpkeep_alive: "".to_string(),
            tunnel: "".to_string(),
            tunnel_device: "".to_string(),
            use_privileged_port: "".to_string(),
            user: "".to_string(),
            user_known_hosts_file: "".to_string(),
            verify_host_key_dns: "".to_string(),
            visual_host_key: "".to_string(),
            xauth_location: "".to_string(),
            args: vec![]
        }
    }
}

//Used to remove the ' or " in a bash alias
fn rm_first_last_char<'a>(value: &'a str, first: bool, last: bool, chars_to_rm: Vec<&str>) -> &'a str {
    let mut chars = value.chars();
    for char in chars_to_rm {
        if first && value.starts_with(char) {
            chars.next();
        }
        if last && value.ends_with(char) {
            chars.next_back();
        }
    }
    chars.as_str()
}

fn read_rc_cfg_file(rc_cfg_path: String, mut server_index: usize, servers: &mut Vec<Server>){
    let file = File::open(rc_cfg_path);
    if file.is_ok() {
        let reader = BufReader::new(file.unwrap());

        for (_index, line) in reader.lines().enumerate() {
            let line = line.unwrap();
            if line.contains("alias") && line.contains("ssh") && line.contains("@") && !line.starts_with("#") {
                let v: Vec<&str> = line.split("=").collect();
                let alias = v[0].strip_prefix("alias").unwrap().trim().to_string();
                let no_quotes: &str = rm_first_last_char(v[1], true, true, vec!["\"", "\'"]);
                let mut args_vec: Vec<String> = no_quotes.split(" ").map(|s| s.to_string()).collect();
                args_vec.retain(|x| x != "ssh");
                let hostname_index = args_vec.iter().position(|x| x.contains("@")).unwrap();
                let host_name = args_vec.remove(hostname_index);
                let server = Server {
                    index: server_index,
                    alias,
                    host_name,
                    args: args_vec,
                    .. Default::default()
                };
                if servers.iter().find(|x|x.alias == server.alias).is_none() {
                    servers.push(server);
                    server_index += 1;
                }
            }
        }
    }
}

fn set_config_server_values(server: &mut Server, line: String) {
    let line_lower = line.to_lowercase();

    if line_lower.contains("addressfamily"){ server.address_family = line }
    else if line_lower.contains("batchmode"){ server.batch_mode = line }
    else if line_lower.contains("bindaddress"){ server.bind_address = line }
    else if line_lower.contains("challengeresponseauthentication"){ server.challenge_response_authentication = line }
    else if line_lower.contains("checkhostip"){ server.check_host_ip = line }
    else if line_lower.contains("cipher"){ server.cipher = line }
    else if line_lower.contains("ciphers"){ server.ciphers = line }
    else if line_lower.contains("clearallforwardings"){ server.clear_all_forwardings = line }
    else if line_lower.contains("compression"){ server.compression = line }
    else if line_lower.contains("compressionlevel"){ server.compression_level = line }
    else if line_lower.contains("connectionattempts"){ server.connection_attempts = line }
    else if line_lower.contains("connecttimeout"){ server.connect_timeout = line }
    else if line_lower.contains("controlmaster"){ server.control_master = line }
    else if line_lower.contains("controlpath"){ server.control_path = line }
    else if line_lower.contains("dynamicforward"){ server.dynamic_forward = line }
    else if line_lower.contains("enablesshkeysign"){ server.enable_sshkeysign = line }
    else if line_lower.contains("escapechar"){ server.escape_char = line }
    else if line_lower.contains("exitonforwardfailure"){ server.exit_on_forward_failure = line }
    else if line_lower.contains("forwardagent"){ server.forward_agent = line }
    else if line_lower.contains("forwardx11"){ server.forward_x11 = line }
    else if line_lower.contains("forwardx11trusted"){ server.forward_x11_trusted = line }
    else if line_lower.contains("gatewayports"){ server.gateway_ports = line }
    else if line_lower.contains("globalknownhostsfile"){ server.global_known_hosts_file = line }
    else if line_lower.contains("gssapiauthentication"){ server.gssapi_authentication = line }
    else if line_lower.contains("gssapikeyexchange"){ server.gssapi_key_exchange = line }
    else if line_lower.contains("gssapiclientidentity"){ server.gssapi_client_identity = line }
    else if line_lower.contains("gssapidelegatecredentials"){ server.gssapi_delegate_credentials = line }
    else if line_lower.contains("gssapirenewalforcesrekey"){ server.gssapi_renewal_forces_rekey = line }
    else if line_lower.contains("gssapitrustdns"){ server.gssapi_trust_dns = line }
    else if line_lower.contains("hashknownhosts"){ server.hash_known_hosts = line }
    else if line_lower.contains("hostbasedauthentication"){ server.hostbased_authentication = line }
    else if line_lower.contains("hostkeyalgorithms"){ server.host_key_algorithms = line }
    else if line_lower.contains("hostkeyalias"){ server.host_key_alias = line }
    else if line_lower.contains("hostname") { server.host_name = line }
    else if line_lower.contains("identitiesonly"){ server.identities_only = line }
    else if line_lower.contains("identityfile"){ server.identity_file = line }
    else if line_lower.contains("kbdinteractiveauthentication"){ server.kbd_interactive_authentication = line }
    else if line_lower.contains("kbdinteractivedevices"){ server.kbd_interactive_devices = line }
    else if line_lower.contains("localcommand"){ server.local_command = line }
    else if line_lower.contains("localforward"){ server.local_forward = line }
    else if line_lower.contains("loglevel"){ server.log_level = line }
    else if line_lower.contains("macs"){ server.macs = line }
    else if line_lower.contains("nohostauthenticationforlocalhost"){ server.no_host_authentication_for_localhost = line }
    else if line_lower.contains("numberofpasswordprompts"){ server.number_of_password_prompts = line }
    else if line_lower.contains("passwordauthentication"){ server.password_authentication = line }
    else if line_lower.contains("permitlocalcommand"){ server.permit_local_command = line }
    else if line_lower.contains("port"){ server.port = line }
    else if line_lower.contains("preferredauthentications"){ server.preferred_authentications = line }
    else if line_lower.contains("protocol"){ server.protocol = line }
    else if line_lower.contains("proxycommand"){ server.proxy_command = line }
    else if line_lower.contains("pubkeyauthentication"){ server.pubkey_authentication = line }
    else if line_lower.contains("rekeylimit"){ server.rekey_limit = line }
    else if line_lower.contains("remoteforward"){ server.remote_forward = line }
    else if line_lower.contains("rhostsrsaauthentication"){ server.rhosts_rsa_authentication = line }
    else if line_lower.contains("rsaauthentication"){ server.rsa_authentication = line }
    else if line_lower.contains("sendenv"){ server.send_env = line }
    else if line_lower.contains("serveralivecountmax"){ server.server_alive_count_max = line }
    else if line_lower.contains("serveraliveinterval"){ server.server_alive_interval = line }
    else if line_lower.contains("smartcarddevice"){ server.smartcard_device = line }
    else if line_lower.contains("stricthostkeychecking"){ server.strict_host_key_checking = line }
    else if line_lower.contains("tcpkeepalive"){ server.tcpkeep_alive = line }
    else if line_lower.contains("tunnel"){ server.tunnel = line }
    else if line_lower.contains("tunneldevice"){ server.tunnel_device = line }
    else if line_lower.contains("useprivilegedport"){ server.use_privileged_port = line }
    else if line_lower.contains("user"){ server.user = line }
    else if line_lower.contains("userknownhostsfile"){ server.user_known_hosts_file = line }
    else if line_lower.contains("verifyhostkeydns"){ server.verify_host_key_dns = line }
    else if line_lower.contains("visualhostkey"){ server.visual_host_key = line }
    else if line_lower.contains("xauthlocation"){ server.xauth_location = line }
}

fn read_ssh_config_file(ssh_cfg_path: String, servers: &mut Vec<Server>){
    let ssh_config_data = fs::read_to_string(ssh_cfg_path).expect("Unable to read file");
    let mut host_num = 0;
    let mut first_run = true;
    for line in ssh_config_data.lines(){
        if line.to_lowercase().starts_with("host"){
            let v: Vec<&str> = line.split(" ").collect();
            let alias = v[1].to_string();
            host_num += 1;
            if first_run {
                first_run = false;
                host_num = 0;
            }
            let server = Server {
                index: host_num,
                alias,
                .. Default::default()
            };
            servers.push( server);

        } else {
            let cleaned_line = rm_first_last_char(line, true, false, vec!["\t"]);
            set_config_server_values(&mut servers[host_num], cleaned_line.to_string());
        }
    }
}

pub fn server_parser() -> Vec<Server> {
    let home_path = match home::home_dir() {
        Some(path) => path,
        None => panic!("Unable to get home directory")
    };
    let mut servers: Vec<Server> = Vec::new();
    let server_index = 1;

    let ssh_cfg_path = home_path.to_str().unwrap().to_owned() + "/.ssh/config";
    read_ssh_config_file(ssh_cfg_path, &mut servers);

    let rc_files = vec![".zshrc", ".bashrc", ".bash_profile", ".zshenv"];

    for rc_file in rc_files {
        let rc_cfg_path = [home_path.to_str().unwrap(), rc_file].join("/");
        read_rc_cfg_file(rc_cfg_path, server_index, &mut servers);
    }

    if !servers.is_empty() && servers[0].alias == "*" {
        servers.remove(0);
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

pub fn connect_to_server(server: &Server, args: Vec<String>){
    if args.iter().any(|x| x.contains("d")) {
        server.display_server_info()
    } else {
        let mut ssh_cmd = Command::new("ssh");
        if server.args.is_empty() {
            ssh_cmd.arg(server.alias.clone());
        } else {
            ssh_cmd.arg(server.host_name.to_string());
            ssh_cmd.args(server.args.clone());
        }
        if args.iter().any(|x| x.contains("vvv")) {
            ssh_cmd.arg("-vvv");
        }
        ssh_cmd.status().expect("process failed to execute");
        println!("SSH Session Terminated")
    }
}