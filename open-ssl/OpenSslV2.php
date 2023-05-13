<?php
/**
 * Created by Maatify.dev
 * User: Maatify.dev
 * Date: 2024-10-14
 * Time: 5:26 PM
 * https://www.Maatify.dev
 */

namespace Maatify\OpenSSL;

use Exception;

abstract class OpenSslV2
{
    protected string $ssl_secret;

    protected string $ssl_algo;

    /**
     * @throws Exception
     */
    public function __construct()
    {
        $this->ssl_algo = 'AES-256-GCM'; // this need to change from Child Class
        if (!in_array(strtolower($this->ssl_algo), openssl_get_cipher_methods())) {
            throw new Exception("Cipher {$this->ssl_algo} is not supported.");
        }
    }

    private function deriveKey($salt): string
    {
        return hash_pbkdf2('sha256', $this->ssl_secret, $salt, 100000, 32, true);  // PBKDF2 with 100,000 iterations
    }

    public function Hash(string $code): string
    {
        $iv_length = openssl_cipher_iv_length($this->ssl_algo);  // Get the IV length (12 bytes)
        $iv = openssl_random_pseudo_bytes($iv_length);  // Generate a random IV

        $salt = openssl_random_pseudo_bytes(16);  // Random salt for PBKDF2
        $key = $this->deriveKey($salt);

        // Encrypt the plaintext and generate the authentication tag
        $ciphertext = openssl_encrypt(
            $code,
            $this->ssl_algo,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // Store salt, IV, tag, and ciphertext together
        return base64_encode($salt . $iv . $tag . $ciphertext);
    }

    public function DeHashed(string $code): string
    {
        if(empty($code)) {
            return '';
        }

        try {
            // Decode the Base64 encoded data from MySQL
            $data = base64_decode($code);

            // Extract the Salt, IV, tag, and ciphertext
            $salt = substr($data, 0, 16);
            $iv_length = openssl_cipher_iv_length($this->ssl_algo);
            $iv = substr($data, 16, $iv_length);
            $tag = substr($data, 16 + $iv_length, 16);
            $ciphertext = substr($data, 16 + $iv_length + 16);

            // Derive the key from the password
            $key = $this->deriveKey($salt);

            // Decrypt the data
            return (string) openssl_decrypt(
                $ciphertext,
                $this->ssl_algo,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
        }catch (Exception $e){
            return '';
        }

    }
}