<?php
/**
 * Created by Maatify.dev
 * User: Maatify.dev
 * Date: 2024-11-18
 * Time: 7:29 PM
 * https://www.Maatify.dev
 */

namespace Maatify\OpenSSL;

use Exception;
use Maatify\Logger\Logger;

abstract class OpenSslV3
{
    protected string $ssl_secret;
    protected string $ssl_algo;

    /**
     * @throws Exception
     */
    public function __construct()
    {
        $this->ssl_algo = 'aes-256-gcm'; // consistent casing
        if (!in_array($this->ssl_algo, openssl_get_cipher_methods())) {
            throw new Exception("Cipher {$this->ssl_algo} is not supported.");
        }
    }

    private function deriveKey(string $salt): string
    {
        return hash_pbkdf2('sha256', $this->ssl_secret, $salt, 100000, 32, true); // 256-bit key
    }

    /**
     * @throws Exception
     */
    public function Hash(string $code): string
    {
        $iv_length = openssl_cipher_iv_length($this->ssl_algo);
        $iv = random_bytes($iv_length); // Ensure proper IV generation

        $salt = random_bytes(16); // 16-byte salt
        $key = $this->deriveKey($salt);

        // Encrypt the data and generate the tag
        $ciphertext = openssl_encrypt(
            $code,
            $this->ssl_algo,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // Ensure the tag is the expected size (e.g., 16 bytes)
        if (strlen($tag) !== 16) {
            throw new Exception("Tag length is invalid.");
        }

        // Concatenate and encode salt, IV, tag, and ciphertext
        return base64_encode($salt . $iv . $tag . $ciphertext);
    }

    public function DeHashed(string $code): string
    {
        if (empty($code)) {
            return '';
        }

        try {
            $data = base64_decode($code, true);
            if ($data === false) {
                throw new Exception("Base64 decoding failed.");
            }

            // Extract salt, IV, tag, and ciphertext
            $salt = substr($data, 0, 16);
            $iv_length = openssl_cipher_iv_length($this->ssl_algo);
            $iv = substr($data, 16, $iv_length);
            $tag = substr($data, 16 + $iv_length, 16);
            $ciphertext = substr($data, 16 + $iv_length + 16);

            // Validate extracted data lengths
            if (strlen($iv) !== $iv_length || strlen($tag) !== 16) {
                throw new Exception("Invalid data structure.");
            }

            // Derive the key
            $key = $this->deriveKey($salt);

            // Decrypt and return the plaintext
            $plaintext = openssl_decrypt(
                $ciphertext,
                $this->ssl_algo,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );

            if ($plaintext === false) {
//                throw new Exception("Decryption failed.");
                return '';
            }

            return $plaintext;
        } catch (Exception $e) {
            // Log the error for debugging if needed
            Logger::RecordLog($e, 'openssl');
            return '';
        }
    }
}
