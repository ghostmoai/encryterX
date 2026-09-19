//! EncryptorX - Interfaz Gráfica Moderna con eframe / egui
//! Diseño profesional sin fuga de información interna ni glifos rotos.

use eframe::egui;
use std::path::PathBuf;

use crate::{
    copy_to_clipboard, decrypt, decrypt_file, encrypt, encrypt_file, generate_secure_password,
    VERSION,
};

#[derive(PartialEq)]
enum ActiveTab {
    Text,
    Files,
    Passwords,
    Steganography,
}

#[derive(PartialEq, Clone, Copy)]
enum StegoSubTab {
    HideText,
    ExtractText,
    HideFile,
    ExtractFile,
    Capacity,
    Metrics,
}

pub struct EncryptorXApp {
    active_tab: ActiveTab,
    // Texto
    input_text: String,
    password_text: String,
    show_password: bool,
    output_text: String,
    // Archivo
    selected_file: Option<PathBuf>,
    file_password: String,
    file_status: String,
    // Contraseñas
    generated_password: String,
    pass_len: usize,
    // Esteganografía
    stego_subtab: StegoSubTab,
    stego_carrier: Option<PathBuf>,
    stego_file_to_hide: Option<PathBuf>,
    stego_second_image: Option<PathBuf>,
    stego_text: String,
    stego_password: String,
    stego_show_password: bool,
    stego_bpc: usize,
    stego_channel_idx: usize,
    stego_output_path: String,
    stego_result_message: String,
    stego_extracted_text: String,
    stego_metrics_info: String,
    // Estado general / Toast
    status_message: String,
    status_is_error: bool,
    toast_message: Option<(String, std::time::Instant)>,
}

impl Default for EncryptorXApp {
    fn default() -> Self {
        Self {
            active_tab: ActiveTab::Text,
            input_text: String::new(),
            password_text: String::new(),
            show_password: false,
            output_text: String::new(),
            selected_file: None,
            file_password: String::new(),
            file_status: String::new(),
            generated_password: generate_secure_password(24),
            pass_len: 24,
            stego_subtab: StegoSubTab::HideText,
            stego_carrier: None,
            stego_file_to_hide: None,
            stego_second_image: None,
            stego_text: String::new(),
            stego_password: String::new(),
            stego_show_password: false,
            stego_bpc: 1,
            stego_channel_idx: 0,
            stego_output_path: String::new(),
            stego_result_message: String::new(),
            stego_extracted_text: String::new(),
            stego_metrics_info: String::new(),
            status_message: "Listo.".to_string(),
            status_is_error: false,
            toast_message: None,
        }
    }
}

impl eframe::App for EncryptorXApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Limpiar toast viejo después de 2.5 segundos
        if let Some((_, time)) = &self.toast_message {
            if time.elapsed().as_secs_f32() > 2.5 {
                self.toast_message = None;
            }
        }

        // Panel Superior / Encabezado
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("EncryptorX").strong().color(egui::Color32::from_rgb(0, 220, 255)));
                ui.colored_label(egui::Color32::from_rgb(180, 190, 254), format!("v{}", VERSION));
            });
            ui.add_space(6.0);

            // Pestañas de Navegación limpias
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, ActiveTab::Text, "  Cifrar / Descifrar Texto  ");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Files, "  Archivos Seguros (.enc)  ");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Passwords, "  Generador de Claves  ");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Steganography, "  Esteganografía en Imágenes  ");
            });
            ui.add_space(6.0);
        });

        // Panel Inferior / Barra de Estado
        egui::TopBottomPanel::bottom("bottom_status").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if self.status_is_error {
                    ui.label(egui::RichText::new("[ERROR]").color(egui::Color32::from_rgb(243, 139, 168)).strong());
                    ui.colored_label(egui::Color32::from_rgb(243, 139, 168), &self.status_message);
                } else {
                    ui.label(egui::RichText::new("[OK]").color(egui::Color32::from_rgb(166, 227, 161)).strong());
                    ui.colored_label(egui::Color32::from_rgb(205, 214, 244), &self.status_message);
                }

                if let Some((toast, _)) = &self.toast_message {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            egui::Color32::from_rgb(0, 240, 255),
                            format!("[ {} ]", toast),
                        );
                    });
                }
            });
            ui.add_space(4.0);
        });

        // Panel Central
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_tab {
                    ActiveTab::Text => self.render_text_tab(ui),
                    ActiveTab::Files => self.render_files_tab(ui),
                    ActiveTab::Passwords => self.render_passwords_tab(ui),
                    ActiveTab::Steganography => self.render_steganography_tab(ui),
                }
            });
        });
    }
}

impl EncryptorXApp {
    fn show_toast(&mut self, msg: &str) {
        self.toast_message = Some((msg.to_string(), std::time::Instant::now()));
    }

    fn render_text_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Texto plano a cifrar O Token cifrado a descifrar:").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(format!("{} caracteres", self.input_text.chars().count()));
            });
        });

        ui.add(
            egui::TextEdit::multiline(&mut self.input_text)
                .hint_text("Escribe o pega aquí el texto a cifrar o el token a descifrar...")
                .desired_rows(6)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );

        ui.add_space(8.0);

        // Fila de Contraseña
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Contraseña / PIN (Opcional):").strong());
            let pwd_edit = egui::TextEdit::singleline(&mut self.password_text)
                .password(!self.show_password)
                .hint_text("Dejar en blanco para modo directo auto-descifrable")
                .desired_width(320.0);
            ui.add(pwd_edit);

            if ui.button(if self.show_password { "Ocultar" } else { "Mostrar" }).clicked() {
                self.show_password = !self.show_password;
            }

            ui.weak("(Protección PBKDF2 de 100.000 iteraciones)");
        });

        ui.add_space(10.0);

        // Botones de acción principales
        ui.horizontal(|ui| {
            let btn_enc = egui::Button::new(
                egui::RichText::new("  Cifrar Texto  ").strong().size(14.0).color(egui::Color32::from_rgb(17, 17, 27)),
            ).fill(egui::Color32::from_rgb(0, 220, 255));

            if ui.add(btn_enc).clicked() {
                if self.input_text.trim().is_empty() {
                    self.status_message = "Por favor, introduce un texto para cifrar.".to_string();
                    self.status_is_error = true;
                } else {
                    let pwd = if self.password_text.is_empty() {
                        None
                    } else {
                        Some(self.password_text.as_str())
                    };
                    match encrypt(&self.input_text, pwd, None) {
                        Ok(token) => {
                            self.output_text = token;
                            let mode_desc = if pwd.is_some() { "con contraseña" } else { "modo directo" };
                            self.status_message = format!(
                                "Texto cifrado exitosamente ({}) • Longitud: {} caracteres",
                                mode_desc, self.output_text.len()
                            );
                            self.status_is_error = false;
                            self.show_toast("Texto cifrado generado con éxito");
                        }
                        Err(e) => {
                            self.status_message = format!("Error al cifrar: {}", e);
                            self.status_is_error = true;
                        }
                    }
                }
            }

            let btn_dec = egui::Button::new(
                egui::RichText::new("  Descifrar Token  ").strong().size(14.0).color(egui::Color32::from_rgb(17, 17, 27)),
            ).fill(egui::Color32::from_rgb(180, 190, 254));

            if ui.add(btn_dec).clicked() {
                if self.input_text.trim().is_empty() {
                    self.status_message = "Pega un token cifrado en el campo superior para descifrarlo.".to_string();
                    self.status_is_error = true;
                } else {
                    let pwd = if self.password_text.is_empty() {
                        None
                    } else {
                        Some(self.password_text.as_str())
                    };
                    match decrypt(&self.input_text, pwd) {
                        Ok(plain) => {
                            self.output_text = plain;
                            self.status_message = "Token descifrado con éxito. Integridad HMAC verificada.".to_string();
                            self.status_is_error = false;
                            self.show_toast("Token descifrado y autenticado");
                        }
                        Err(e) => {
                            self.status_message = format!("Error al descifrar: {}", e);
                            self.status_is_error = true;
                        }
                    }
                }
            }

            if ui.button("  Limpiar Campos  ").clicked() {
                self.input_text.clear();
                self.output_text.clear();
                self.status_message = "Campos restablecidos.".to_string();
                self.status_is_error = false;
            }
        });

        ui.add_space(12.0);

        // Área de Salida
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Resultado (Token generado / Texto descifrado):").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Copiar al Portapapeles").clicked() {
                    if self.output_text.is_empty() {
                        self.status_message = "No hay contenido para copiar.".to_string();
                        self.status_is_error = true;
                    } else {
                        copy_to_clipboard(&self.output_text);
                        self.show_toast("Copiado al portapapeles");
                        self.status_message = "Resultado copiado al portapapeles.".to_string();
                        self.status_is_error = false;
                    }
                }
            });
        });

        ui.add(
            egui::TextEdit::multiline(&mut self.output_text)
                .hint_text("El resultado generado aparecerá aquí...")
                .desired_rows(8)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
    }

    fn render_files_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.heading("Cifrado y Descifrado Seguro de Archivos");
        ui.label("Protección criptográfica para cualquier formato (PDF, documentos, imágenes, zips, ejecutables).");
        ui.label("Incluye autenticación estricta e integridad anti-manipulación.");
        ui.add_space(12.0);

        ui.group(|ui| {
            ui.horizontal(|ui| {
                if ui.button("  Seleccionar Archivo...  ").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.selected_file = Some(path);
                        self.file_status = "Archivo listo para procesar.".to_string();
                    }
                }

                if let Some(path) = &self.selected_file {
                    ui.label(format!("Ruta: {}", path.display()));
                } else {
                    ui.weak("Ningún archivo seleccionado");
                }
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Contraseña para el archivo (Opcional):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.file_password)
                        .password(true)
                        .hint_text("Enter para modo directo sin contraseña")
                        .desired_width(260.0),
                );
            });

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let btn_enc = egui::Button::new(
                    egui::RichText::new("  Cifrar a .enc  ").strong().color(egui::Color32::from_rgb(17, 17, 27)),
                ).fill(egui::Color32::from_rgb(0, 220, 255));

                if ui.add(btn_enc).clicked() {
                    if let Some(path) = &self.selected_file {
                        let pwd = if self.file_password.is_empty() { None } else { Some(self.file_password.as_str()) };
                        match encrypt_file(path, None::<&str>, pwd) {
                            Ok(out_path) => {
                                self.file_status = format!("Archivo cifrado creado: {}", out_path.display());
                                self.status_message = format!("Guardado en: {}", out_path.display());
                                self.status_is_error = false;
                                self.show_toast("Archivo cifrado con éxito");
                            }
                            Err(e) => {
                                self.file_status = format!("Error: {}", e);
                                self.status_message = format!("Error al cifrar archivo: {}", e);
                                self.status_is_error = true;
                            }
                        }
                    } else {
                        self.file_status = "Seleccione un archivo primero.".to_string();
                    }
                }

                let btn_dec = egui::Button::new(
                    egui::RichText::new("  Descifrar Archivo  ").strong().color(egui::Color32::from_rgb(17, 17, 27)),
                ).fill(egui::Color32::from_rgb(166, 227, 161));

                if ui.add(btn_dec).clicked() {
                    if let Some(path) = &self.selected_file {
                        let pwd = if self.file_password.is_empty() { None } else { Some(self.file_password.as_str()) };
                        match decrypt_file(path, None::<&str>, pwd) {
                            Ok(out_path) => {
                                self.file_status = format!("Archivo descifrado restaurado: {}", out_path.display());
                                self.status_message = format!("Restaurado en: {}", out_path.display());
                                self.status_is_error = false;
                                self.show_toast("Archivo descifrado y verificado");
                            }
                            Err(e) => {
                                self.file_status = format!("Error: {}", e);
                                self.status_message = format!("Error al descifrar archivo: {}", e);
                                self.status_is_error = true;
                            }
                        }
                    } else {
                        self.file_status = "Seleccione un archivo primero.".to_string();
                    }
                }
            });

            if !self.file_status.is_empty() {
                ui.add_space(8.0);
                ui.label(egui::RichText::new(&self.file_status).color(egui::Color32::from_rgb(180, 190, 254)));
            }
        });
    }

    fn render_passwords_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.heading("Generador Criptográfico de Contraseñas");
        ui.label("Generación aleatoria de alta entropía asistida por el hardware del sistema.");
        ui.add_space(12.0);

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Longitud de la clave:");
                ui.add(egui::Slider::new(&mut self.pass_len, 12..=64).text("caracteres"));
            });

            ui.add_space(10.0);

            if ui.button("  Generar Nueva Contraseña  ").clicked() {
                self.generated_password = generate_secure_password(self.pass_len);
                self.show_toast("Nueva clave generada");
            }

            ui.add_space(12.0);

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Contraseña:").strong());
                ui.add(
                    egui::TextEdit::singleline(&mut self.generated_password)
                        .desired_width(380.0)
                        .font(egui::TextStyle::Monospace),
                );

                if ui.button("Copiar").clicked() {
                    copy_to_clipboard(&self.generated_password);
                    self.show_toast("Clave copiada");
                }

                if ui.button("Usar para Cifrar").clicked() {
                    self.password_text = self.generated_password.clone();
                    self.file_password = self.generated_password.clone();
                    self.show_toast("Aplicada a campos de contraseña");
                }
            });
        });
    }

    fn render_steganography_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Esteganografía en Imágenes (Pixel Shuffling)");
        ui.label("Incrusta y extrae datos de forma invisible en imágenes PNG o BMP con cifrado PBKDF2 y HMAC anti-tamper.");
        ui.add_space(8.0);

        // Barra de Modos de Esteganografía
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.stego_subtab, StegoSubTab::HideText, "  Ocultar Texto  ");
            ui.selectable_value(&mut self.stego_subtab, StegoSubTab::ExtractText, "  Extraer Texto  ");
            ui.selectable_value(&mut self.stego_subtab, StegoSubTab::HideFile, "  Ocultar Archivo  ");
            ui.selectable_value(&mut self.stego_subtab, StegoSubTab::ExtractFile, "  Extraer Archivo  ");
            ui.selectable_value(&mut self.stego_subtab, StegoSubTab::Capacity, "  Capacidad  ");
            ui.selectable_value(&mut self.stego_subtab, StegoSubTab::Metrics, "  Métricas PSNR  ");
        });

        ui.add_space(10.0);

        let channel_str = match self.stego_channel_idx {
            1 => "B",
            2 => "R",
            3 => "G",
            _ => "RGB",
        };

        ui.group(|ui| {
            match self.stego_subtab {
                StegoSubTab::HideText => {
                    ui.label(egui::RichText::new("1. Seleccionar Imagen Portadora (PNG o BMP):").strong());
                    ui.horizontal(|ui| {
                        if ui.button("  Explorar Imagen...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Imágenes soportadas (*.png, *.bmp)", &["png", "bmp"])
                                .pick_file()
                            {
                                if self.stego_output_path.is_empty() {
                                    if let Some(parent) = path.parent() {
                                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("foto");
                                        self.stego_output_path = parent.join(format!("{}_stego.png", stem)).to_string_lossy().to_string();
                                    }
                                }
                                self.stego_carrier = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_carrier {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna imagen seleccionada");
                        }
                    });

                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("2. Mensaje de Texto Secreto a Ocultar:").strong());
                    ui.add(
                        egui::TextEdit::multiline(&mut self.stego_text)
                            .hint_text("Escribe aquí el texto confidencial a camuflar...")
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );

                    ui.add_space(8.0);
                    self.render_stego_crypto_and_advanced_controls(ui);

                    ui.add_space(10.0);
                    let btn = egui::Button::new(
                        egui::RichText::new("  Inyectar Texto en Imagen (Pixel Shuffling)  ")
                            .strong()
                            .size(13.5)
                            .color(egui::Color32::from_rgb(17, 17, 27)),
                    ).fill(egui::Color32::from_rgb(0, 220, 255));

                    if ui.add(btn).clicked() {
                        let carrier = self.stego_carrier.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                        let text = self.stego_text.clone();
                        let pwd = self.stego_password.clone();
                        let out_path = if self.stego_output_path.is_empty() {
                            "stego_output.png".to_string()
                        } else {
                            self.stego_output_path.clone()
                        };

                        if carrier.is_empty() {
                            self.status_message = "Seleccione una imagen portadora.".to_string();
                            self.status_is_error = true;
                        } else if text.trim().is_empty() {
                            self.status_message = "Escriba un texto para ocultar.".to_string();
                            self.status_is_error = true;
                        } else {
                            let bpc_str = self.stego_bpc.to_string();
                            let mut args = vec![
                                "hide-text",
                                "-i", &carrier,
                                "-t", &text,
                                "-o", &out_path,
                                "-b", &bpc_str,
                                "-c", channel_str,
                            ];
                            if !pwd.is_empty() {
                                args.push("-p");
                                args.push(&pwd);
                            }

                            match run_stego_cli(&args) {
                                Ok(res) => {
                                    self.stego_result_message = res.trim().to_string();
                                    self.status_message = format!("Texto inyectado con éxito en: {}", out_path);
                                    self.status_is_error = false;
                                    self.show_toast("Texto inyectado con éxito");

                                    // Calcular métricas automáticamente
                                    if let Ok(m) = run_stego_cli(&["metrics", "-orig", &carrier, "-stego", &out_path]) {
                                        self.stego_metrics_info = m.trim().to_string();
                                    }
                                }
                                Err(e) => {
                                    self.stego_result_message = format!("Error: {}", e);
                                    self.status_message = format!("Fallo al inyectar texto: {}", e);
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }
                }

                StegoSubTab::ExtractText => {
                    ui.label(egui::RichText::new("1. Seleccionar Imagen Esteganográfica con Texto Oculto:").strong());
                    ui.horizontal(|ui| {
                        if ui.button("  Explorar Imagen Estego...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Imágenes (*.png, *.bmp)", &["png", "bmp"])
                                .pick_file()
                            {
                                self.stego_carrier = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_carrier {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna imagen seleccionada");
                        }
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Contraseña (si se usó al ocultar):");
                        let pwd_edit = egui::TextEdit::singleline(&mut self.stego_password)
                            .password(!self.stego_show_password)
                            .hint_text("Dejar vacío si no tiene contraseña")
                            .desired_width(260.0);
                        ui.add(pwd_edit);
                        if ui.button(if self.stego_show_password { "Ocultar" } else { "Mostrar" }).clicked() {
                            self.stego_show_password = !self.stego_show_password;
                        }
                    });

                    ui.add_space(10.0);
                    let btn = egui::Button::new(
                        egui::RichText::new("  Extraer Texto Oculto  ")
                            .strong()
                            .size(13.5)
                            .color(egui::Color32::from_rgb(17, 17, 27)),
                    ).fill(egui::Color32::from_rgb(180, 190, 254));

                    if ui.add(btn).clicked() {
                        let carrier = match &self.stego_carrier {
                            Some(p) => p.to_str().unwrap_or(""),
                            None => "",
                        };
                        if carrier.is_empty() {
                            self.status_message = "Seleccione la imagen esteganográfica.".to_string();
                            self.status_is_error = true;
                        } else {
                            let mut args = vec!["extract-text", "-i", carrier];
                            if !self.stego_password.is_empty() {
                                args.push("-p");
                                args.push(&self.stego_password);
                            }

                            match run_stego_cli(&args) {
                                Ok(raw) => {
                                    let lines: Vec<&str> = raw.lines().collect();
                                    let mut rec = Vec::new();
                                    let mut capture = false;
                                    for l in &lines {
                                        if l.starts_with("------------------") {
                                            capture = !capture;
                                            continue;
                                        }
                                        if capture {
                                            rec.push(*l);
                                        }
                                    }
                                    let final_text = if rec.is_empty() { raw } else { rec.join("\n") };
                                    self.stego_extracted_text = final_text;
                                    self.stego_result_message = "Texto extraído y verificado con HMAC.".to_string();
                                    self.status_message = "Texto secreto recuperado con éxito.".to_string();
                                    self.status_is_error = false;
                                    self.show_toast("Texto recuperado");
                                }
                                Err(e) => {
                                    self.stego_result_message = format!("Error al extraer: {}", e);
                                    self.status_message = format!("Error al extraer texto: {}", e);
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }

                    if !self.stego_extracted_text.is_empty() {
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Texto Recuperado:").strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Copiar Texto").clicked() {
                                    copy_to_clipboard(&self.stego_extracted_text);
                                    self.show_toast("Texto copiado al portapapeles");
                                }
                            });
                        });
                        ui.add(
                            egui::TextEdit::multiline(&mut self.stego_extracted_text)
                                .desired_rows(5)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                    }
                }

                StegoSubTab::HideFile => {
                    ui.label(egui::RichText::new("1. Seleccionar Imagen Portadora (PNG o BMP):").strong());
                    ui.horizontal(|ui| {
                        if ui.button("  Explorar Imagen...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Imágenes soportadas (*.png, *.bmp)", &["png", "bmp"])
                                .pick_file()
                            {
                                if self.stego_output_path.is_empty() {
                                    if let Some(parent) = path.parent() {
                                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("foto");
                                        self.stego_output_path = parent.join(format!("{}_stego.png", stem)).to_string_lossy().to_string();
                                    }
                                }
                                self.stego_carrier = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_carrier {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna imagen seleccionada");
                        }
                    });

                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("2. Archivo Secreto a Ocultar (PDF, ZIP, DOCX, EXE, etc.):").strong());
                    ui.horizontal(|ui| {
                        if ui.button("  Explorar Archivo a Ocultar...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.stego_file_to_hide = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_file_to_hide {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ningún archivo seleccionado");
                        }
                    });

                    ui.add_space(8.0);
                    self.render_stego_crypto_and_advanced_controls(ui);

                    ui.add_space(10.0);
                    let btn = egui::Button::new(
                        egui::RichText::new("  Incrustar Archivo en Imagen  ")
                            .strong()
                            .size(13.5)
                            .color(egui::Color32::from_rgb(17, 17, 27)),
                    ).fill(egui::Color32::from_rgb(0, 220, 255));

                    if ui.add(btn).clicked() {
                        let carrier = self.stego_carrier.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                        let file = self.stego_file_to_hide.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                        let pwd = self.stego_password.clone();
                        let out_path = if self.stego_output_path.is_empty() {
                            "stego_output.png".to_string()
                        } else {
                            self.stego_output_path.clone()
                        };

                        if carrier.is_empty() || file.is_empty() {
                            self.status_message = "Seleccione la imagen portadora y el archivo a ocultar.".to_string();
                            self.status_is_error = true;
                        } else {
                            let bpc_str = self.stego_bpc.to_string();
                            let mut args = vec![
                                "hide-file",
                                "-i", &carrier,
                                "-f", &file,
                                "-o", &out_path,
                                "-b", &bpc_str,
                                "-c", channel_str,
                            ];
                            if !pwd.is_empty() {
                                args.push("-p");
                                args.push(&pwd);
                            }

                            match run_stego_cli(&args) {
                                Ok(res) => {
                                    self.stego_result_message = res.trim().to_string();
                                    self.status_message = format!("Archivo incrustado en: {}", out_path);
                                    self.status_is_error = false;
                                    self.show_toast("Archivo incrustado en imagen");
                                    if let Ok(m) = run_stego_cli(&["metrics", "-orig", &carrier, "-stego", &out_path]) {
                                        self.stego_metrics_info = m.trim().to_string();
                                    }
                                }
                                Err(e) => {
                                    self.stego_result_message = format!("Error: {}", e);
                                    self.status_message = format!("Fallo al incrustar archivo: {}", e);
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }
                }

                StegoSubTab::ExtractFile => {
                    ui.label(egui::RichText::new("1. Seleccionar Imagen Esteganográfica con Archivo Oculto:").strong());
                    ui.horizontal(|ui| {
                        if ui.button("  Explorar Imagen Estego...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Imágenes (*.png, *.bmp)", &["png", "bmp"])
                                .pick_file()
                            {
                                self.stego_carrier = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_carrier {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna imagen seleccionada");
                        }
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Carpeta donde restaurar el archivo:");
                        if ui.button("  Seleccionar Carpeta...  ").clicked() {
                            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                                self.stego_output_path = dir.to_string_lossy().to_string();
                            }
                        }
                        if !self.stego_output_path.is_empty() {
                            ui.label(&self.stego_output_path);
                        } else {
                            ui.weak("Carpeta actual por defecto");
                        }
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Contraseña de descifrado (si se protegió):");
                        let pwd_edit = egui::TextEdit::singleline(&mut self.stego_password)
                            .password(!self.stego_show_password)
                            .hint_text("Dejar en blanco si no tiene clave")
                            .desired_width(260.0);
                        ui.add(pwd_edit);
                        if ui.button(if self.stego_show_password { "Ocultar" } else { "Mostrar" }).clicked() {
                            self.stego_show_password = !self.stego_show_password;
                        }
                    });

                    ui.add_space(10.0);
                    let btn = egui::Button::new(
                        egui::RichText::new("  Extraer y Restaurar Archivo  ")
                            .strong()
                            .size(13.5)
                            .color(egui::Color32::from_rgb(17, 17, 27)),
                    ).fill(egui::Color32::from_rgb(166, 227, 161));

                    if ui.add(btn).clicked() {
                        let carrier = match &self.stego_carrier {
                            Some(p) => p.to_str().unwrap_or(""),
                            None => "",
                        };
                        if carrier.is_empty() {
                            self.status_message = "Seleccione la imagen esteganográfica.".to_string();
                            self.status_is_error = true;
                        } else {
                            let out_dir = if self.stego_output_path.is_empty() {
                                "."
                            } else {
                                self.stego_output_path.as_str()
                            };
                            let mut args = vec!["extract-file", "-i", carrier, "-o", out_dir];
                            if !self.stego_password.is_empty() {
                                args.push("-p");
                                args.push(&self.stego_password);
                            }

                            match run_stego_cli(&args) {
                                Ok(res) => {
                                    self.stego_result_message = res.trim().to_string();
                                    self.status_message = "Archivo secreto recuperado con éxito.".to_string();
                                    self.status_is_error = false;
                                    self.show_toast("Archivo restaurado");
                                }
                                Err(e) => {
                                    self.stego_result_message = format!("Error al extraer: {}", e);
                                    self.status_message = format!("Fallo al extraer archivo: {}", e);
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }
                }

                StegoSubTab::Capacity => {
                    ui.label(egui::RichText::new("1. Seleccionar Imagen a Inspeccionar:").strong());
                    ui.horizontal(|ui| {
                        if ui.button("  Explorar Imagen...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Imágenes (*.png, *.bmp)", &["png", "bmp"])
                                .pick_file()
                            {
                                self.stego_carrier = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_carrier {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna imagen seleccionada");
                        }
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Bits por canal a evaluar:");
                        ui.radio_value(&mut self.stego_bpc, 1, "1 bit (Ultra Sigilo)");
                        ui.radio_value(&mut self.stego_bpc, 2, "2 bits (Alto Sigilo)");
                        ui.radio_value(&mut self.stego_bpc, 4, "4 bits (Capacidad Máxima)");
                    });

                    ui.horizontal(|ui| {
                        ui.label("Canales a evaluar:");
                        ui.radio_value(&mut self.stego_channel_idx, 0, "RGB (Todos)");
                        ui.radio_value(&mut self.stego_channel_idx, 1, "Azul (B - Mayor sigilo)");
                    });

                    ui.add_space(10.0);
                    if ui.button("  Calcular Capacidad Neta de Almacenamiento  ").clicked() {
                        let carrier = match &self.stego_carrier {
                            Some(p) => p.to_str().unwrap_or(""),
                            None => "",
                        };
                        if carrier.is_empty() {
                            self.status_message = "Seleccione una imagen primero.".to_string();
                            self.status_is_error = true;
                        } else {
                            let bpc_str = self.stego_bpc.to_string();
                            let args = vec!["info", "-i", carrier, "-b", &bpc_str, "-c", channel_str];
                            match run_stego_cli(&args) {
                                Ok(res) => {
                                    self.stego_result_message = res.trim().to_string();
                                    self.status_message = "Capacidad calculada con éxito.".to_string();
                                    self.status_is_error = false;
                                }
                                Err(e) => {
                                    self.stego_result_message = format!("Error: {}", e);
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }
                }

                StegoSubTab::Metrics => {
                    ui.label(egui::RichText::new("Calcular Distorsión Visual y Sigilo Científico (PSNR / MSE):").strong());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Imagen Original (Portadora):");
                        if ui.button("  Explorar Original...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.stego_carrier = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_carrier {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna");
                        }
                    });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Imagen con Esteganografía:");
                        if ui.button("  Explorar Estego...  ").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.stego_second_image = Some(path);
                            }
                        }
                        if let Some(p) = &self.stego_second_image {
                            ui.label(format!("{}", p.display()));
                        } else {
                            ui.weak("Ninguna");
                        }
                    });

                    ui.add_space(10.0);
                    if ui.button("  Ejecutar Análisis Forense de Fidelidad Visual (PSNR / MSE)  ").clicked() {
                        let orig = match &self.stego_carrier {
                            Some(p) => p.to_str().unwrap_or(""),
                            None => "",
                        };
                        let stego = match &self.stego_second_image {
                            Some(p) => p.to_str().unwrap_or(""),
                            None => "",
                        };
                        if orig.is_empty() || stego.is_empty() {
                            self.status_message = "Seleccione la imagen original y la imagen esteganográfica.".to_string();
                            self.status_is_error = true;
                        } else {
                            let args = vec!["metrics", "-orig", orig, "-stego", stego];
                            match run_stego_cli(&args) {
                                Ok(res) => {
                                    self.stego_metrics_info = res.trim().to_string();
                                    self.status_message = "Métricas PSNR calculadas exitosamente.".to_string();
                                    self.status_is_error = false;
                                }
                                Err(e) => {
                                    self.stego_metrics_info = format!("Error: {}", e);
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }
                }
            }

            // Bloques de Resultado y Métricas
            if !self.stego_result_message.is_empty() {
                ui.add_space(12.0);
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Resultado de la Operación:").strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Copiar").clicked() {
                                copy_to_clipboard(&self.stego_result_message);
                                self.show_toast("Resultado copiado");
                            }
                        });
                    });
                    ui.label(
                        egui::RichText::new(&self.stego_result_message)
                            .color(egui::Color32::from_rgb(180, 190, 254))
                            .monospace(),
                    );
                });
            }

            if !self.stego_metrics_info.is_empty() {
                ui.add_space(10.0);
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Certificación de Calidad Visual (Forense):").strong().color(egui::Color32::from_rgb(0, 240, 255)));
                    ui.label(
                        egui::RichText::new(&self.stego_metrics_info)
                            .color(egui::Color32::from_rgb(166, 227, 161))
                            .monospace(),
                    );
                });
            }
        });
    }

    fn render_stego_crypto_and_advanced_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Contraseña de blindaje (Opcional):");
            let pwd_edit = egui::TextEdit::singleline(&mut self.stego_password)
                .password(!self.stego_show_password)
                .hint_text("Sin contraseña: modo directo")
                .desired_width(260.0);
            ui.add(pwd_edit);
            if ui.button(if self.stego_show_password { "Ocultar" } else { "Mostrar" }).clicked() {
                self.stego_show_password = !self.stego_show_password;
            }
            ui.weak("(PBKDF2 100.000 rondas + HMAC-SHA256)");
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Ruta imagen de salida (PNG):");
            ui.add(
                egui::TextEdit::singleline(&mut self.stego_output_path)
                    .hint_text("stego_output.png")
                    .desired_width(360.0),
            );
        });

        ui.add_space(6.0);
        ui.collapsing("Configuración Avanzada de Esteganografía (Bits por canal y Canales)", |ui| {
            ui.horizontal(|ui| {
                ui.label("Bits por canal (LSB):");
                ui.radio_value(&mut self.stego_bpc, 1, "1 bit (Ultra Sigilo, PSNR > 65 dB)");
                ui.radio_value(&mut self.stego_bpc, 2, "2 bits (Alto Sigilo, PSNR > 52 dB)");
                ui.radio_value(&mut self.stego_bpc, 4, "4 bits (Capacidad Máxima, PSNR > 38 dB)");
            });

            ui.horizontal(|ui| {
                ui.label("Canales a usar:");
                ui.radio_value(&mut self.stego_channel_idx, 0, "RGB (Todos los colores)");
                ui.radio_value(&mut self.stego_channel_idx, 1, "Azul (B - Menor sensibilidad del ojo humano)");
                ui.radio_value(&mut self.stego_channel_idx, 2, "Rojo (R)");
                ui.radio_value(&mut self.stego_channel_idx, 3, "Verde (G)");
            });
        });
    }
}

fn run_stego_cli(args: &[&str]) -> Result<String, String> {
    use std::process::Command;
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let mut cmd = Command::new("python");
    cmd.arg("-m").arg("encryptorx.stego");
    for arg in args {
        cmd.arg(arg);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            cmd.current_dir(parent);
        }
    }

    #[cfg(windows)]
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

    match cmd.output() {
        Ok(out) => {
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            } else {
                let err = String::from_utf8_lossy(&out.stderr).to_string();
                if err.trim().is_empty() {
                    Err(String::from_utf8_lossy(&out.stdout).to_string())
                } else {
                    Err(err)
                }
            }
        }
        Err(e) => Err(format!("No se pudo ejecutar el motor Python: {}", e)),
    }
}

pub fn run_gui() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([940.0, 720.0])
            .with_min_inner_size([740.0, 540.0])
            .with_title(format!("EncryptorX v{}", VERSION)),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "EncryptorX",
        options,
        Box::new(|cc| {
            configure_fonts_and_style(&cc.egui_ctx);
            Ok(Box::new(EncryptorXApp::default()))
        }),
    );
}

fn configure_fonts_and_style(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Intentar cargar fuentes del sistema Windows (Segoe UI) para máxima nitidez
    #[cfg(windows)]
    {
        if let Ok(font_data) = std::fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
            fonts.font_data.insert(
                "segoe_ui".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(font_data)),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.insert(0, "segoe_ui".to_owned());
            }
        }
    }

    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(18, 19, 28);
    visuals.window_fill = egui::Color32::from_rgb(24, 25, 36);
    visuals.extreme_bg_color = egui::Color32::from_rgb(14, 15, 22);
    visuals.faint_bg_color = egui::Color32::from_rgb(28, 30, 44);

    ctx.set_visuals(visuals);
}
