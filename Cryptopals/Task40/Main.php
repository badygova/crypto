<?php declare(strict_types = 1);

namespace Cryptopals\Task40;

use Cryptopals\Task39\RSA;

/**
 * Class Main
 * @package Cryptopals\Task40
 */
class Main
{
  /**
   * @param array $residues
   * @param array $moduli
   * @return \GMP
   */
  protected function CRT(array $residues, array $moduli): \GMP
    {
        $x = 0;
        $n = 1;

        foreach ($moduli as $m) {
            $n *= $m;
        }

        foreach ($moduli as $i => $m) {
            $nm = $n / $m;
            $x += $residues[$i] * gmp_gcdext($m, $nm)['t'] * $nm;
        }

        return $x % $n;
    }

  /**
   * @return bool
   */
  function execute(): bool
    {
        $e = gmp_init(3);
        $plaintext = gmp_init(0xcafebabe);
        printf("Plaintext: %x\n", $plaintext);

        list(, , $public1) = RSA::generatePQND(256, $e);
        list(, , $public2) = RSA::generatePQND(256, $e);
        list(, , $public3) = RSA::generatePQND(256, $e);

        $cipher1 = RSA::encrypt($plaintext, $e, $public1);
        $cipher2 = RSA::encrypt($plaintext, $e, $public2);
        $cipher3 = RSA::encrypt($plaintext, $e, $public3);

        $crt = $this->CRT([$cipher1, $cipher2, $cipher3], [$public1, $public2, $public3]);
        $decrypted = gmp_root($crt, 3);

        printf("Recovered: %x\n", $decrypted);

        return $plaintext == $decrypted;
    }
}
