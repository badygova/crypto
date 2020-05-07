<?php declare(strict_types = 1);

namespace Cryptopals\Task41;

use Cryptopals\Task39\RSA;

class DecryptAPI
{
  /**
   * @var RSA
   */
  protected $rsa;

  /**
   * @var \GMP|resource
   */
  protected $e;
  /**
   * @var
   */
  protected $n;
  /**
   * @var
   */
  protected $d;

  /**
   * @var array
   */
  protected $cache = [];

  /**
   * DecryptAPI constructor.
   * @param RSA $rsa
   */
  function __construct(RSA $rsa)
    {
        $this->rsa = $rsa;

        $this->e = gmp_init(65537);
        list(, , $this->n, $this->d) = $this->rsa->generatePQND(256, $this->e);

        return true;
    }

  /**
   * @return array
   */
  function publicKey(): array
    {
        return [$this->e, $this->n];
    }

  /**
   * @param string $blob
   * @return string
   * @throws \Exception
   */
  function decryptBlob(string $blob): string
    {
        $hash = sha1($blob);
        if (isset($this->cache[$hash])) {
            throw new \Exception('Cannot decrypt the same blob twice');
        }
        $this->cache[$hash] = time();

        $message = gmp_import($blob);
        $decrypted = $this->rsa->decrypt($message, $this->d, $this->n);

        return gmp_export($decrypted);
    }
}
