mod keys;

fn main() {
    println!("Khimy - chat chiffre de bout en bout");
    println!("=== Generation des cles Signal ===\n");

    match keys::generate_all_keys() {
        Ok(keys) => {
            println!("[OK] Cles generees avec succes :");
            println!("     Registration ID  : {}", keys.registration_id);
            println!("     Signed Pre-Key   : id={}", u32::from(keys.signed_pre_key.0));
            println!("     Kyber Pre-Key    : id={}", u32::from(keys.kyber_pre_key.0));
            println!("     One-Time Pre-Keys: {} generees", keys.pre_keys.len());
            println!();
            println!("Prochaine etape : implementer session.rs (X3DH + Double Ratchet).");
        }
        Err(e) => {
            eprintln!("[ERREUR] {:?}", e);
        }
    }
}
