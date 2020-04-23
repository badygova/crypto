<?php declare(strict_types = 1);

namespace Cryptopals\Task33;

/**
 * Class DH
 * @package Cryptopals\Task33
 */
class DH
{
    private $p;
    private $g;

  /**
   * DH constructor.
   */
  function __construct()
    {
        $this->p = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e08
        8a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c2
        45e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286
        651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3562085
        52bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);
        $this->g = gmp_init(2);
    }

  /**
   * @return \GMP
   */
  function generatePrivate(): \GMP
    {
        return gmp_random(60);
    }

  /**
   * @param \GMP $private
   * @return \GMP
   */
  function generatePublic(\GMP $private): \GMP
    {
        return gmp_powm($this->g, $private, $this->p);
    }

  /**
   * @param \GMP $private
   * @param \GMP $public
   * @return \GMP
   */
  function generateShared(\GMP $private, \GMP $public): \GMP
    {
        return gmp_powm($public, $private, $this->p);
    }

  /**
   * @return string
   */
  function p(): string
    {
        return gmp_strval($this->p, 16);
    }

  /**
   * @param string|null $val
   * @return string
   */
  function g(string $val = null): string
    {
        if (is_string($val)) {
            $this->g = gmp_init($val, 16);
        }

        return gmp_strval($this->g, 16);
    }
}
