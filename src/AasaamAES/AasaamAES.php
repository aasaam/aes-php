<?php

declare(strict_types=1);

namespace AasaamAES;

use Throwable;

use function base64_decode;
use function base64_encode;
use function json_decode;
use function json_encode;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_random_pseudo_bytes;
use function strlen;
use function substr;
use function time;

use const JSON_UNESCAPED_UNICODE;
use const OPENSSL_RAW_DATA;

class AasaamAES
{
    /**
     * Binary encryption key
     *
     * @var string
     */
    private $key = '';

    /**
     * Create instance
     *
     * @param string $key Base64 encoded random bytes with length 32
     */
    public function __construct(string $key)
    {
        $this->key = base64_decode($key);
    }

    /**
     * Generate encryption key
     *
     * @return string Base64 encoded random bytes with length 32
     */
    public static function generateKey(): string
    {
        return base64_encode(openssl_random_pseudo_bytes(32));
    }

    /**
     * Encrypt message with time to live
     *
     * @param string  $message message Message to be encrypted
     * @param integer $ttl     Number of time to live in second
     * @return string Encrypted message with time to live
     */
    public function encryptTTL(string $message, int $ttl): string
    {
        return $this->encrypt(
            json_encode(
                [
                    'message' => $message,
                    'ttl'     => time() + $ttl,
                ],
                JSON_UNESCAPED_UNICODE
            ),
        );
    }

    /**
     * Decrypted message that contain time to live
     *
     * @param  string $encryptedTtlMessage Encrypted message with time to live
     * @return string Original message or empty string on failure
     */
    public function decryptTTL(string $encryptedTtlMessage): string
    {
        try {
            $json = json_decode($this->decrypt($encryptedTtlMessage), true);
            if ($json['ttl'] >= time()) {
                return $json['message'];
            }
        } catch (Throwable $e) {
            // nothing
        }
        return '';
    }

    /**
     * Encrypt message
     *
     * @param string $message Message to be encrypted
     * @return string Encrypted message
     */
    public function encrypt(string $message): string
    {
        $iv  = openssl_random_pseudo_bytes(12);
        $tag = '';

        $encrypted = openssl_encrypt(
            $message,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        return base64_encode($iv . $encrypted . $tag);
    }

    /**
     * Decrypt message
     *
     * @param string $encryptedMessage Encrypted message
     * @return string Original message or empty string on failure
     */
    public function decrypt(string $encryptedMessage): string
    {
        $packet = base64_decode($encryptedMessage);

        $iv        = substr($packet, 0, 12);
        $encrypted = substr($packet, 12, strlen($packet) - 28);
        $tag       = substr($packet, -16);

        try {
            $data = openssl_decrypt(
                $encrypted,
                'aes-256-gcm',
                $this->key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
            );
            if ($data !== false) {
                return $data;
            }
        } catch (Throwable $e) {
            // nothing
        }
        return '';
    }
}
