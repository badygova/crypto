<?php declare(strict_types = 1);

namespace Cryptopals\Task35;

use AES\CBC;
use Cryptopals\Task34\PKC7;

/**
 * Class MITM
 * @package Cryptopals\Task35
 */
class MITM
{
    protected $cbc;

  /**
   * MITM constructor.
   * @param CBC $cbc
   * @param ConversationEntity $A
   * @param ConversationEntity $B
   */
  function __construct(CBC $cbc, ConversationEntity $A, ConversationEntity $B)
    {
        $this->cbc = $cbc;

        $A->onSend = function(string $data) use ($B) {
            $B->receive($this->sniffData($data));
        };

        $B->onSend = function(string $data) use ($A) {
            $A->receive($this->sniffData($data));
        };
    }

  /**
   * @param string $data
   * @return string
   */
  function sniffData(string $data): string
    {
        return $data;
    }
}
