<?php declare(strict_types = 1);

namespace Cryptopals\Task41;

use Cryptopals\Task39\RSA;

/**
 * Class Main
 * @package Cryptopals\Task41
 */
class Main
{
  /**
   * @var RSA
   */
  protected $rsa;
  /**
   * @var DecryptAPI
   */
  protected $decryptAPI;

  /**
   * Main constructor.
   * @param RSA $rsa
   * @param DecryptAPI $decryptAPI
   */
  function __construct(RSA $rsa, DecryptAPI $decryptAPI)
    {
        $this->rsa = $rsa;
        $this->decryptAPI = $decryptAPI;
    }

  /**
   * @return string
   */
  function captureCiphertext(): string
    {
        list($e, $n) = $this->decryptAPI->publicKey();

        $plaintext = gmp_import('the matasano crypto challenges');
        $encrypted = $this->rsa->encrypt($plaintext, $e, $n);

        $ciphertext = gmp_export($encrypted);
        return $ciphertext;
    }

  /**
   * @return bool
   */
  function execute(): bool
    {
        $ciphertext = $this->captureCiphertext();

        $actualPlaintext = $this->decryptAPI->decryptBlob($ciphertext);

        print 'Captured ciphertext: ' . bin2hex($ciphertext) . "\n\n";

        list($e, $n) = $this->decryptAPI->publicKey();
        $multiplier = 2;

        $cPrime = gmp_export((gmp_powm($multiplier, $e, $n) * gmp_import($ciphertext)) % $n);
        $pPrime = $this->decryptAPI->decryptBlob($cPrime);
        $p = gmp_export((gmp_import($pPrime) / $multiplier) % $n);

        print "Recovered plaintext: {$p}\n";

        return $actualPlaintext === $p;
    }
}
