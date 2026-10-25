            if let Ok(path)=std::env::var("GO_PORT_FORGERY_DIR") {
                let path=std::path::PathBuf::from(path);
                std::fs::create_dir_all(&path).unwrap();
                let key=tree.mixed_verifier_bytes(&prover.roots()).unwrap();
                let pin=Tree::mixed_class_key_digest(&key);
                std::fs::write(path.join("class-key.digest"),pin.iter().map(|b|format!("{b:02x}")).collect::<String>()).unwrap();
                std::fs::write(path.join("root.bin"),root.to_bytes()).unwrap();
                std::fs::write(path.join("claims.bin"),forged_set.to_bytes()).unwrap();
                std::fs::write(path.join("seal.bin"),seal.to_bytes()).unwrap();
                std::fs::write(path.join("child-root.bin"),child.to_bytes()).unwrap();
            }
