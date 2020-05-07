<?php declare(strict_types = 1);

namespace Cryptopals\Task39;

use Cryptopals\Solution;

/**
 * Class Main
 * @package Cryptopals\Task39
 */
class Main implements Solution
{
  /**
   * @return bool
   */
  function execute(): bool
    {
        $e = gmp_init(3);

        list(, , $n, $d) = RSA::generatePQND(256, $e);

        /*
        $public = [$e, $n];
        $private = [$d, $n];
        */

        $c = RSA::encrypt(gmp_init(0xbabe), $e, $n);
        $m = RSA::decrypt($c, $d, $n);

        return $m == 0xbabe;
    }
}
