<?php declare(strict_types = 1);

namespace Cryptopals\Task46;

/**
 * Class Main
 * @package Cryptopals\Task46
 */
class Main
{
  /**
   * @var ParityOracle
   */
  protected $parityOracle;

  /**
   * Main constructor.
   * @param ParityOracle $parityOracle
   */
  function __construct(ParityOracle $parityOracle)
    {
        $this->parityOracle = $parityOracle;
    }

  /**
   * @return bool
   */
  function execute(): bool
    {
        list($e, $n) = $this->parityOracle->publicKey();
        $ciphertext = $this->parityOracle->ciphertext();

        $double = gmp_powm(2, $e, $n) ;
        $multiplier = gmp_init(1);

        for ($i = 1; $i <= 1024; $i++) {
            $ciphertext = ($ciphertext * $double) % $n;
            $multiplier <<= 1;

            if (!$this->parityOracle->oracle($ciphertext)) {
                $multiplier--;
            }

            $recovered = ($multiplier * $n) >> $i;
            print gmp_export($recovered) . "\n";
        }

        return true;
    }
}
