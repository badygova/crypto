<?php declare(strict_types = 1);

namespace Cryptopals\Task39;

/**
 * Class RSA
 * @package Cryptopals\Task39
 */
class RSA
{
  /**
   * @param int $bits
   * @param \GMP $e
   * @return array
   */
    static function generatePQND(int $bits, \GMP $e): array
      {
        $bytes = $bits >> 3;

        do {
            do {
                $p = gmp_nextprime(gmp_random_bits($bits));
                $q = gmp_nextprime(gmp_random_bits($bits));
            } while (
                $p == $q ||
                strlen(gmp_export($p)) > $bytes ||
                strlen(gmp_export($q)) > $bytes
            );

            $d = gmp_invert($e, ($p - 1) * ($q - 1));
        } while (
            $d === false ||
            gmp_gcd($p, $e) != 1 ||
            gmp_gcd($q, $e) != 1
        );

        return [$p, $q, $p * $q, $d];
    }

  /**
   * @param \GMP $message
   * @param \GMP $e
   * @param \GMP $n
   * @return \GMP
   */
    static function encrypt(\GMP $message, \GMP $e, \GMP $n): \GMP
      {
        return gmp_powm($message, $e, $n);
      }

  /**
   * @param \GMP $message
   * @param \GMP $d
   * @param \GMP $n
   * @return \GMP
   */
    static function decrypt(\GMP $message, \GMP $d, \GMP $n): \GMP
      {
        return gmp_powm($message, $d, $n);
      }

}
