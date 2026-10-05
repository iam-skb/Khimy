mod keys;
mod session;
mod stores;
mod stores_wrappers;

use libsignal_protocol::*;
use stores::InMemoryStores;

fn main() {
    println!("Khimy - chat chiffre de bout en bout");
    println!("=== Test chiffrement/dechiffrement ===\n");

    // 1. Générer les clés d'Alice et Bob
    let alice_keys = keys::generate_all_keys().expect("Alice keys");
    let bob_keys = keys::generate_all_keys().expect("Bob keys");

    let alice_address = ProtocolAddress::new("alice".to_string(), DeviceId::new(1).unwrap());
    let bob_address = ProtocolAddress::new("bob".to_string(), DeviceId::new(1).unwrap());

    let mut alice_store =
        InMemoryStores::new(alice_keys.identity_key_pair.clone(), alice_keys.registration_id);
    let mut bob_store =
        InMemoryStores::new(bob_keys.identity_key_pair.clone(), bob_keys.registration_id);

    // 2. Peupler le store de Bob avec SES clés (pour qu'il puisse déchiffrer)
    {
        let mut spk = bob_store.signed_pre_keys.lock().unwrap();
        spk.insert(bob_keys.signed_pre_key.0, bob_keys.signed_pre_key.1.clone());
    }
    {
        let mut kpk = bob_store.kyber_pre_keys.lock().unwrap();
        kpk.insert(bob_keys.kyber_pre_key.0, bob_keys.kyber_pre_key.1.clone());
    }
    {
        let mut pk = bob_store.pre_keys.lock().unwrap();
        for (id, record) in &bob_keys.pre_keys {
            pk.insert(*id, record.clone());
        }
    }

    println!("[OK] Alice et Bob ont leurs cles");
    println!();

    // 3. Construire le PreKeyBundle de Bob
    let bob_pre_key = bob_keys.pre_keys[0].clone();
    let bob_signed_pre_key = bob_keys.signed_pre_key.clone();
    let bob_kyber_pre_key = bob_keys.kyber_pre_key.clone();

    let bob_bundle = PreKeyBundle::new(
        bob_keys.registration_id,
        DeviceId::new(1).unwrap(),
        Some((bob_pre_key.0, bob_pre_key.1.public_key().unwrap())),
        bob_signed_pre_key.0,
        bob_signed_pre_key.1.public_key().unwrap(),
        bob_signed_pre_key.1.signature().unwrap().to_vec(),
        bob_kyber_pre_key.0,
        bob_kyber_pre_key.1.public_key().unwrap(),
        bob_kyber_pre_key.1.signature().unwrap().to_vec(),
        *bob_keys.identity_key_pair.identity_key(),
    )
    .expect("PreKeyBundle Bob");

    println!("[OK] PreKeyBundle de Bob construit");
    println!();

    // 4. Alice établit la session avec Bob
    let mut rng = rand::rng();
    println!("[1] Alice etablit la session...");
    futures::executor::block_on(session::establish_session(
        &mut alice_store,
        &alice_address,
        &bob_address,
        &bob_bundle,
        &mut rng,
    ))
    .expect("establish_session Alice");
    println!("    OK");
    println!();

    // 5. Alice chiffre un message
    let plaintext = b"Salut Bob ! Ceci est un message chiffre.";
    println!("[2] Alice chiffre : {:?}", String::from_utf8_lossy(plaintext));
    let ciphertext = futures::executor::block_on(session::encrypt_message(
        &mut alice_store,
        &alice_address,
        &bob_address,
        plaintext,
        &mut rng,
    ))
    .expect("encrypt_message");
    println!("    Ciphertext : {} octets", ciphertext.serialize().len());
    println!();

    // 6. Bob déchiffre le premier message
    println!("[3] Bob dechiffre le premier message...");
    let prekey_msg = match ciphertext {
        CiphertextMessage::PreKeySignalMessage(m) => m,
        _ => panic!("Attendu PreKeySignalMessage"),
    };

    let decrypted = futures::executor::block_on(session::decrypt_prekey_message(
        &mut bob_store,
        &bob_address,
        &alice_address,
        &prekey_msg,
        &mut rng,
    ))
    .expect("decrypt_prekey_message Bob");

    println!("    Message dechiffre : {:?}", String::from_utf8_lossy(&decrypted));
    println!();

    if decrypted == plaintext {
        println!(">>> SUCCES : le message a bien ete chiffre puis dechiffre !");
    } else {
        println!(">>> ECHEC : le message dechiffre ne correspond pas.");
    }
}
