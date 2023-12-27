pub mod aes_encryption{
    use aes::Aes256;
    use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, generic_array::GenericArray, KeyInit};
    use rand::{rngs::OsRng, RngCore};
    use sha256::{digest, try_digest};

    #[derive(Clone)]
    pub struct Message{
        pub hash:String,
        pub value:Vec<u8>
    }

    #[derive(Clone)]
    pub struct FileMessage{
        pub filename:String,
        pub file:Message
    }

    impl Message{
        pub fn new(value: Vec<u8>) -> Message {
            let hash = digest(value.clone());
            Message {value:value.clone(), hash: hash}
        }
    }

    impl FileMessage{
        pub fn new(filename:String, raw_file: Vec<u8>) -> FileMessage{
            let message = Message::new(raw_file);
            FileMessage {filename:filename, file: message}
        }
    }

    pub trait AesEngine{
        fn encrypt_aes_256_cbc(&self, key: &[u8; 32]) -> Vec<u8>;
        fn decrypt_aes_256_cbc(&self, ciphertext: Vec<u8>, key: &[u8; 32]) -> Message;
    }

    impl AesEngine for Message{

        fn encrypt_aes_256_cbc(&self, key: &[u8; 32]) -> Vec<u8> {
            let mut iv = [0u8; 16];
            let mut rng = OsRng;
            rng.fill_bytes(&mut iv);
            let cipher = Aes256::new(GenericArray::from_slice(key));
            let mut ciphertext:Vec<u8> = iv.to_vec();
            let mut prev_block:[u8;16] = iv;
            let plaintext = self.value.clone();
            for block in plaintext.chunks(16) {
                let mut plaintext_block = [0u8; 16];
                plaintext_block[..block.len()].copy_from_slice(block);
                for i in 0..16 {
                    plaintext_block[i] ^= prev_block[i];
                }
                let mut ciphertext_block = plaintext_block.clone();
                cipher.encrypt_block(GenericArray::from_mut_slice(&mut ciphertext_block));
                prev_block = ciphertext_block;
                ciphertext.extend_from_slice(&ciphertext_block);
            }
            ciphertext.clone()
        }

        fn decrypt_aes_256_cbc(&self, ciphertext: Vec<u8>, key: &[u8; 32]) -> Message {
            if ciphertext.len() < 16 {
                return Message::new(vec![0u8;0])
            }
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&ciphertext[..16]);
            let cipher = Aes256::new(GenericArray::from_slice(key));
            let mut output = vec![0u8; ciphertext.len() - 16];
            let mut prev_block = iv;
            for (i, block) in ciphertext[16..].chunks(16).enumerate() {
                if block.len() < 16 {
                    let mut padded_block = [0u8; 16];
                    padded_block[..block.len()].copy_from_slice(block);
                    for j in block.len()..16 {
                        padded_block[j] = 16 - (block.len() as u8);
                    }
                    block_cipher_decrypt(&mut output[i * 16..], &cipher, &prev_block, &padded_block);
                } else {
                    let mut decrypted_block = [0u8; 16];
                    block_cipher_decrypt(&mut decrypted_block, &cipher, &prev_block, block);
                    prev_block.copy_from_slice(&block[..16]);
                    output[i * 16..(i + 1) * 16].copy_from_slice(&decrypted_block);
                }
            }
	    remove_padding(&mut output);
            Message::new(output)
        }
    }

    fn remove_padding(input:&mut Vec<u8>){
	if input.len() > 1{
	    let mut slice_index = input.len() - 1;
	    while slice_index > 0 && input[slice_index] == 0u8 {
		slice_index-=1;
	    }
    	input.truncate(slice_index + 1);
	} 
    }

    fn block_cipher_decrypt(output: &mut [u8], cipher: &Aes256, prev_block: &[u8], input: &[u8]) {
        let mut input_block = [0u8; 16];
        input_block.copy_from_slice(input);
        let mut output_block = input_block.clone();
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut output_block));
        for i in 0..16 {
            output[i] = output_block[i] ^ prev_block[i];
        }
    }

    pub fn get_key(passkey: String) -> [u8;32]{
        let digest_key = digest(passkey).clone();
        let digest_longkey = digest_key.as_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest_longkey[0..32]);
        key
}
}
