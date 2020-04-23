<?php declare(strict_types = 1);

namespace Cryptopals\Task35;

use AES\CBC;
use Cryptopals\Task34\PKC7;

class MITM
{
    protected $cbc;

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

    function sniffData(string $data): string
    {
        return $data;
    }
}
