use encryptorx::{encrypt, decrypt, VERSION};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("EncryptorX Rust CLI v{}", VERSION);
        println!("Uso:");
        println!("  {} -e \"mensaje\" [password] [separador: $, %, &, #]", args[0]);
        println!("  {} -d \"token\" [password]", args[0]);
        println!("  {} --test", args[0]);
        return;
    }

    let cmd = &args[1];

    if cmd == "--test" {
        let msg = "Prueba nativa de EncryptorX en Rust!";
        println!("[TEST RUST] Cifrando: '{}'", msg);
        match encrypt(msg, None, '$') {
            Ok(token) => {
                println!("[TEST RUST] Token (len {}):\n{}", token.len(), token);
                match decrypt(&token, None) {
                    Ok(dec) => {
                        println!("[TEST RUST] Descifrado exitoso: '{}'", dec);
                        if dec == msg {
                            println!("[TEST RUST] RUST NATIVE TEST PASSED 100%!");
                        } else {
                            eprintln!("[TEST RUST] ERROR: Mismatch!");
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("[TEST RUST] Error al descifrar: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("[TEST RUST] Error al cifrar: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if cmd == "-e" && args.len() >= 3 {
        let text = &args[2];
        let pwd = if args.len() >= 4 && !args[3].is_empty() { Some(args[3].as_str()) } else { None };
        let sep = if args.len() >= 5 { args[4].chars().next().unwrap_or('$') } else { '$' };

        match encrypt(text, pwd, sep) {
            Ok(token) => println!("{}", token),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if cmd == "-d" && args.len() >= 3 {
        let token = &args[2];
        let pwd = if args.len() >= 4 && !args[3].is_empty() { Some(args[3].as_str()) } else { None };

        match decrypt(token, pwd) {
            Ok(pt) => println!("{}", pt),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    eprintln!("Comando no reconocido.");
    std::process::exit(1);
}
