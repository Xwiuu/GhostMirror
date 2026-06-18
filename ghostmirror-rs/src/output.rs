use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("{{\"error\":\"serialization failed: {}\"}}", e);
            std::process::exit(1);
        }
    }
}
