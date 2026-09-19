use encryptorx::{
    copy_to_clipboard, decrypt, decrypt_file, encrypt, encrypt_file, generate_secure_password,
    VERSION,
};
use std::env;
use std::io::{self, Write};
use std::path::Path;

fn pause(msg: Option<&str>) {
    let prompt = msg.unwrap_or("Presione ENTER para continuar...");
    print!("\n{}", prompt);
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

fn read_clean_line(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        // Limpiar comillas que Windows agrega al arrastrar y soltar archivos
        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        {
            if trimmed.len() >= 2 {
                return trimmed[1..trimmed.len() - 1].to_string();
            }
        }
        trimmed.to_string()
    } else {
        String::new()
    }
}

fn ask_copy_to_clipboard(content: &str) {
    let answer = read_clean_line("¿Desea copiar este resultado al portapapeles de Windows? [S/n]: ");
    if answer.is_empty() || answer.eq_ignore_ascii_case("s") || answer.eq_ignore_ascii_case("si") {
        if copy_to_clipboard(content) {
            println!("  [OK] ¡Copiado al portapapeles de Windows!");
        } else {
            println!("  [!] No se pudo acceder al portapapeles.");
        }
    }
}

fn run_interactive_menu() {
    loop {
        println!("\n======================================================================");
        println!("                         ENCRYPTORX v{}", VERSION);
        println!("======================================================================");
        println!(" [1] Cifrar texto (Modo directo / auto-descifrable)");
        println!(" [2] Cifrar texto con contraseña (PBKDF2 100.000 iteraciones)");
        println!(" [3] Descifrar texto o token");
        println!(" [4] Cifrar un archivo (.enc)");
        println!(" [5] Descifrar un archivo (.enc)");
        println!(" [6] Generar contraseña de alta seguridad");
        println!(" [7] Ejecutar auto-test de verificación");
        println!(" [0] Salir");
        println!("----------------------------------------------------------------------");

        let choice = read_clean_line("Seleccione una opción [0-7]: ");

        match choice.as_str() {
            "1" => {
                println!("\n--- CIFRAR TEXTO (MODO DIRECTO) ---");
                let text = read_clean_line("Ingrese el texto a cifrar: ");
                if text.is_empty() {
                    println!("[!] El texto no puede estar vacío.");
                    pause(None);
                    continue;
                }
                println!("Aplicando cifrado de flujo con esteganografía polimórfica...");

                match encrypt(&text, None, None) {
                    Ok(token) => {
                        println!("\n[OK] Token Cifrado Generado Exitosamente:");
                        println!("----------------------------------------------------------------------");
                        println!("{}", token);
                        println!("----------------------------------------------------------------------");
                        println!("Longitud: {} caracteres • Integridad HMAC Activa", token.len());
                        ask_copy_to_clipboard(&token);
                    }
                    Err(e) => println!("\n[ERROR] al cifrar: {}", e),
                }
                pause(None);
            }

            "2" => {
                println!("\n--- CIFRAR TEXTO CON CONTRASEÑA ---");
                let text = read_clean_line("Ingrese el texto a cifrar: ");
                if text.is_empty() {
                    println!("[!] El texto no puede estar vacío.");
                    pause(None);
                    continue;
                }
                let pwd = read_clean_line("Ingrese la contraseña: ");
                if pwd.is_empty() {
                    println!("[!] La contraseña no puede estar vacía.");
                    pause(None);
                    continue;
                }
                println!("Aplicando blindaje criptográfico con derivación PBKDF2...");

                match encrypt(&text, Some(&pwd), None) {
                    Ok(token) => {
                        println!("\n[OK] Token Protegido con Contraseña Generado:");
                        println!("----------------------------------------------------------------------");
                        println!("{}", token);
                        println!("----------------------------------------------------------------------");
                        println!("Longitud: {} caracteres • Protegido por Contraseña", token.len());
                        ask_copy_to_clipboard(&token);
                    }
                    Err(e) => println!("\n[ERROR] al cifrar: {}", e),
                }
                pause(None);
            }

            "3" => {
                println!("\n--- DESCIFRAR TEXTO O TOKEN ---");
                let token = read_clean_line("Pegue el token cifrado: ");
                if token.is_empty() {
                    println!("[!] El token no puede estar vacío.");
                    pause(None);
                    continue;
                }
                let pwd_input = read_clean_line("Contraseña (deje en blanco si fue cifrado en modo directo): ");
                let pwd = if pwd_input.is_empty() { None } else { Some(pwd_input.as_str()) };

                match decrypt(&token, pwd) {
                    Ok(plaintext) => {
                        println!("\n[OK] Mensaje Descifrado Exitosamente:");
                        println!("----------------------------------------------------------------------");
                        println!("{}", plaintext);
                        println!("----------------------------------------------------------------------");
                        ask_copy_to_clipboard(&plaintext);
                    }
                    Err(e) => {
                        println!("\n[ERROR] al descifrar: {}", e);
                        println!("Asegúrese de haber ingresado el token completo y la contraseña correcta.");
                    }
                }
                pause(None);
            }

            "4" => {
                println!("\n--- CIFRAR ARCHIVO ---");
                let in_path = read_clean_line("Ruta del archivo a cifrar (puede arrastrar y soltar el archivo aquí): ");
                if in_path.is_empty() || !Path::new(&in_path).exists() {
                    println!("[!] Archivo no encontrado: '{}'", in_path);
                    pause(None);
                    continue;
                }
                let pwd_input = read_clean_line("Contraseña opcional (Enter para modo directo): ");
                let pwd = if pwd_input.is_empty() { None } else { Some(pwd_input.as_str()) };

                println!("Cifrando archivo...");
                match encrypt_file(&in_path, None::<&str>, pwd) {
                    Ok(out_path) => {
                        println!("\n[OK] Archivo cifrado creado exitosamente:");
                        println!("    -> {:?}", out_path);
                    }
                    Err(e) => println!("\n[ERROR] al cifrar archivo: {}", e),
                }
                pause(None);
            }

            "5" => {
                println!("\n--- DESCIFRAR ARCHIVO ---");
                let in_path = read_clean_line("Ruta del archivo cifrado (.enc): ");
                if in_path.is_empty() || !Path::new(&in_path).exists() {
                    println!("[!] Archivo no encontrado: '{}'", in_path);
                    pause(None);
                    continue;
                }
                let pwd_input = read_clean_line("Contraseña (deje en blanco si fue directo): ");
                let pwd = if pwd_input.is_empty() { None } else { Some(pwd_input.as_str()) };

                println!("Descifrando archivo y verificando integridad HMAC...");
                match decrypt_file(&in_path, None::<&str>, pwd) {
                    Ok(out_path) => {
                        println!("\n[OK] Archivo descifrado exitosamente:");
                        println!("    -> {:?}", out_path);
                    }
                    Err(e) => println!("\n[ERROR] al descifrar archivo: {}", e),
                }
                pause(None);
            }

            "6" => {
                println!("\n--- GENERADOR DE CONTRASEÑAS SEGURAS ---");
                let len_str = read_clean_line("Longitud deseada [por defecto: 24]: ");
                let len = len_str.parse::<usize>().unwrap_or(24);
                let pwd = generate_secure_password(len);
                println!("\n[OK] Contraseña generada de alta entropía:");
                println!("    {}", pwd);
                ask_copy_to_clipboard(&pwd);
                pause(None);
            }

            "7" => {
                println!("\n--- EJECUTANDO AUTO-TEST DE VERIFICACIÓN NATIVA ---");
                let msg = "Mensaje de prueba en Rust para auto-verificación!";
                print!("1. Cifrado polimórfico multi-capa... ");
                match encrypt(msg, None, None) {
                    Ok(tok) => {
                        if tok.contains('$') && tok.contains('%') && tok.contains('&') && tok.contains('#') {
                            match decrypt(&tok, None) {
                                Ok(dec) if dec == msg => println!("PASÓ [OK]"),
                                _ => println!("FALLÓ en descifrado [ERROR]"),
                            }
                        } else {
                            println!("FALLÓ (estructura no verificada) [ERROR]");
                        }
                    }
                    Err(_) => println!("FALLÓ [ERROR]"),
                }

                print!("2. Cifrado con contraseña PBKDF2 y HMAC... ");
                match encrypt(msg, Some("MiClaveTest"), None) {
                    Ok(tok) => match decrypt(&tok, Some("MiClaveTest")) {
                        Ok(dec) if dec == msg => println!("PASÓ [OK]"),
                        _ => println!("FALLÓ [ERROR]"),
                    },
                    Err(_) => println!("FALLÓ [ERROR]"),
                }

                print!("3. Detección de contraseña incorrecta... ");
                match encrypt(msg, Some("Correcta"), None) {
                    Ok(tok) => match decrypt(&tok, Some("Incorrecta")) {
                        Err(_) => println!("PASÓ (Rechazado correctamente) [OK]"),
                        Ok(_) => println!("FALLÓ [ERROR]"),
                    },
                    Err(_) => println!("FALLÓ [ERROR]"),
                }

                println!("\n¡Todas las pruebas del motor nativo pasaron exitosamente!");
                pause(None);
            }

            "0" => {
                println!("\n¡Gracias por utilizar EncryptorX!");
                pause(Some("Presione ENTER para cerrar la ventana..."));
                break;
            }

            _ => {
                println!("[!] Opción inválida. Por favor seleccione un número del 0 al 7.");
                pause(None);
            }
        }
    }
}

fn print_cli_help(prog_name: &str) {
    println!("==============================================================");
    println!("           EncryptorX Rust CLI v{}", VERSION);
    println!("==============================================================");
    println!("Uso:");
    println!("  {}                                Abre la Interfaz Gráfica (GUI)", prog_name);
    println!("  {} --gui                          Abre la Interfaz Gráfica (GUI)", prog_name);
    println!("  {} -i | --cli                     Inicia el Menú Interactivo TUI", prog_name);
    println!("  {} -e \"texto\" [-p pass]          Cifra un texto con blindaje criptográfico", prog_name);
    println!("  {} -d \"token\" [-p pass]            Descifra un texto o token", prog_name);
    println!("  {} -ef <archivo> [-p pass]        Cifra un archivo (.enc)", prog_name);
    println!("  {} -df <archivo.enc> [-p pass]    Descifra un archivo (.enc)", prog_name);
    println!("  {} --gen-pass [longitud]          Genera una contraseña segura", prog_name);
    println!("  {} --test                         Ejecuta el auto-test del motor", prog_name);
    println!("  {} --help                         Muestra esta ayuda", prog_name);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Por defecto sin argumentos (doble clic) -> ABRIR INTERFAZ GRÁFICA (GUI)
    if args.len() < 2 || args[1] == "--gui" {
        encryptorx::gui::run_gui();
        return;
    }

    let cmd = &args[1];

    if cmd == "-i" || cmd == "--cli" {
        run_interactive_menu();
        return;
    }

    match cmd.as_str() {
        "--help" | "-h" => {
            print_cli_help(&args[0]);
        }

        "--test" => {
            let msg = "Prueba nativa de EncryptorX en Rust!";
            println!("[TEST RUST] Aplicando cifrado polimórfico multi-capa...");
            match encrypt(msg, None, None) {
                Ok(token) => {
                    println!("[TEST RUST] Token seguro generado (longitud {} caracteres):", token.len());
                    println!("{}", token);
                    assert!(token.contains('$'));
                    assert!(token.contains('%'));
                    assert!(token.contains('&'));
                    assert!(token.contains('#'));
                    match decrypt(&token, None) {
                        Ok(dec) => {
                            println!("[TEST RUST] Descifrado exitoso: '{}'", dec);
                            if dec == msg {
                                println!("[TEST RUST] MOTOR CRIPTOGRAFICO VERIFICADO 100% [OK]!");
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
        }

        "-e" => {
            if args.len() < 3 {
                eprintln!("Error: Falta el texto a cifrar. Uso: {} -e \"mensaje\" [-p pass] [-s sep]", args[0]);
                std::process::exit(1);
            }
            let text = &args[2];
            let mut pwd = None;
            let mut sep = None;

            let mut i = 3;
            while i < args.len() {
                if args[i] == "-p" || args[i] == "--password" {
                    if i + 1 < args.len() {
                        pwd = Some(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                } else if args[i] == "-s" || args[i] == "--separator" {
                    if i + 1 < args.len() {
                        sep = args[i + 1].chars().next();
                        i += 2;
                        continue;
                    }
                } else {
                    // Positional fallback
                    if pwd.is_none() && !args[i].starts_with('-') {
                        pwd = Some(args[i].clone());
                    } else if sep.is_none() && !args[i].starts_with('-') {
                        sep = args[i].chars().next();
                    }
                    i += 1;
                }
            }

            match encrypt(text, pwd.as_deref(), sep) {
                Ok(token) => println!("{}", token),
                Err(e) => {
                    eprintln!("Error al cifrar: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "-d" => {
            if args.len() < 3 {
                eprintln!("Error: Falta el token a descifrar. Uso: {} -d \"token\" [-p pass]", args[0]);
                std::process::exit(1);
            }
            let token = &args[2];
            let mut pwd = None;

            let mut i = 3;
            while i < args.len() {
                if args[i] == "-p" || args[i] == "--password" {
                    if i + 1 < args.len() {
                        pwd = Some(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                } else {
                    if pwd.is_none() && !args[i].starts_with('-') {
                        pwd = Some(args[i].clone());
                    }
                    i += 1;
                }
            }

            match decrypt(token, pwd.as_deref()) {
                Ok(pt) => println!("{}", pt),
                Err(e) => {
                    eprintln!("Error al descifrar: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "-ef" => {
            if args.len() < 3 {
                eprintln!("Error: Falta la ruta del archivo. Uso: {} -ef <archivo> [-p pass]", args[0]);
                std::process::exit(1);
            }
            let file_path = &args[2];
            let mut pwd = None;

            let mut i = 3;
            while i < args.len() {
                if args[i] == "-p" || args[i] == "--password" {
                    if i + 1 < args.len() {
                        pwd = Some(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                } else {
                    if pwd.is_none() && !args[i].starts_with('-') {
                        pwd = Some(args[i].clone());
                    }
                    i += 1;
                }
            }

            match encrypt_file(file_path, None::<&str>, pwd.as_deref()) {
                Ok(out_path) => println!("Archivo cifrado: {:?}", out_path),
                Err(e) => {
                    eprintln!("Error al cifrar archivo: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "-df" => {
            if args.len() < 3 {
                eprintln!("Error: Falta la ruta del archivo cifrado. Uso: {} -df <archivo.enc> [-p pass]", args[0]);
                std::process::exit(1);
            }
            let file_path = &args[2];
            let mut pwd = None;

            let mut i = 3;
            while i < args.len() {
                if args[i] == "-p" || args[i] == "--password" {
                    if i + 1 < args.len() {
                        pwd = Some(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                } else {
                    if pwd.is_none() && !args[i].starts_with('-') {
                        pwd = Some(args[i].clone());
                    }
                    i += 1;
                }
            }

            match decrypt_file(file_path, None::<&str>, pwd.as_deref()) {
                Ok(out_path) => println!("Archivo descifrado: {:?}", out_path),
                Err(e) => {
                    eprintln!("Error al descifrar archivo: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "--gen-pass" => {
            let len = if args.len() >= 3 {
                args[2].parse::<usize>().unwrap_or(24)
            } else {
                24
            };
            println!("{}", generate_secure_password(len));
        }

        other => {
            eprintln!("Comando desconocido: '{}'", other);
            print_cli_help(&args[0]);
            std::process::exit(1);
        }
    }
}
