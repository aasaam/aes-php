<?php

declare(strict_types=1);

namespace AasaamAESTest;

use AasaamAES\AasaamAES;
use PHPUnit\Framework\TestCase;

use function file_get_contents;
use function is_string;
use function json_decode;
use function sleep;

final class AasaamAESTest extends TestCase
{
    public function testGenerateKey(): void
    {
        $this->assertTrue(is_string(AasaamAES::generateKey()));
    }

    public function testEncryptionDecryption(): void
    {
        $test = json_decode(file_get_contents("./test.json"), true);

        $aes = new AasaamAES($test['key']);

        $encrypted = $aes->encrypt($test['message']);

        $decryptedTest = $aes->decrypt($test['encrypted']);

        $this->assertEquals($test['message'], $decryptedTest);

        $encryptedTtl = $aes->encryptTTL($test['message'], 1);
        $decryptedTtl = $aes->decryptTTL($encryptedTtl);

        $decryptedTtl2 = $aes->decryptTTL($test['encryptedTTL']);
        $this->assertEquals($decryptedTtl2, $test['message']);

        $decryptedFailed1 = $aes->decryptTTL($encrypted);
        $decryptedFailed2 = $aes->decryptTTL("2");
        $decryptedFailed3 = $aes->decrypt("2");

        $this->assertTrue($decryptedTtl === $test['message']);
        $this->assertTrue($decryptedFailed1 === '');
        $this->assertTrue($decryptedFailed2 === '');

        $aes2 = new AasaamAES($test['key'] . 'a');

        $this->assertTrue($aes2->decrypt("2") === '');
    }

    public function testDecryptionTTLException(): void
    {
        $test = json_decode(file_get_contents("./test.json"), true);

        $aes = new AasaamAES($test['key']);

        $encrypted = $aes->encryptTTL($test['message'], 1);
        sleep(2);
        $result = $aes->decryptTTL($encrypted);
        $this->assertTrue($result === '');
    }

    public function testHashKey(): void
    {
        $test = json_decode(file_get_contents("./test.json"), true);

        $mustSecureMessage = $test['message'];

        $clientDataSender = [
            '1.1.1.1',
            'user-agent',
        ];

        $clientDataSenderKey = AasaamAES::generateHashKey($test['key'], $clientDataSender);

        $aes = new AasaamAES($clientDataSenderKey);

        $networkData = $aes->encrypt($mustSecureMessage);

        $sameData = $aes->decrypt($networkData);

        $sameData2 = $aes->decrypt($test['networkData']);

        $this->assertEquals($sameData, $mustSecureMessage);

        $this->assertEquals($sameData2, $mustSecureMessage);
    }
}
