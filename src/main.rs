mod keys;
mod stores;

fn main() {
    println!("Khimy - chat chiffre de bout en bout");

    match keys::generate_all_keys() {
        Ok(keys) => {
            println!("Cles generees :");
            println!("  Registration ID : {}", keys.registration_id);
            println!("  Signed Pre-Key  : id={}", u32::from(keys.signed_pre_key.0));
            println!("  Kyber Pre-Key   : id={}", u32::from(keys.kyber_pre_key.0));
            println!("  One-Time Pre-Keys : {} generees", keys.pre_keys.len());
        }
        Err(e) => {
            eprintln!("Erreur : {:?}", e);
        }
    }
}
