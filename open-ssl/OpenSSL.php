<?php
/**
 * Created by Maatify.dev
 * User: Maatify.dev
 * Date: 2023-03-21
 * Time: 3:46 PM
 */

namespace Maatify\OpenSSL;

abstract class OpenSSL
{
    protected string $ssl_secret;

    protected string $ssl_algo;

    public function Hash(string $code): string
    {
        return (string) openssl_encrypt($code, $this->ssl_algo, $this->ssl_secret);
    }

    public function DeHashed(string $code): string
    {
        return (string) openssl_decrypt($code, $this->ssl_algo, $this->ssl_secret);
    }
}