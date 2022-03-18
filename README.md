# Quick SSH
An SSH parser that reads .zshrc, .bashrc, .bash_profile and .zshenv for ssh aliases and lists them, then allows you to select a connection.

## Install
Install rust
```
git clone https://github.com/GramSea/QuickSSH.git
cd quick_ssh
cargo build --release

cp /target/release/quick_ssh folder_on_path
ex: arch -> cp target/release/quick_ssh ~/.local/bin/
```


## Use
call ```qssh``` to view list of servers

```qssh al``` will print all the servers as their aliases\
```-vvv``` for verbose ssh
