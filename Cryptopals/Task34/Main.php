<?php declare(strict_types = 1);

namespace Cryptopals\Task34;

use AES\CBC;
use Cryptopals\Task33\DH;

class Main
{
    protected $dh;
    protected $cbc;

    function __construct(CBC $cbc, DH $dh)
    {
        $this->dh = $dh;
        $this->cbc = $cbc;
    }

    function execute(): bool
    {
        print "Testing normal comms:\n\n";

        $A = new ConversationEntity('A', $this->dh, $this->cbc);
        $B = new ConversationEntity('B', $this->dh, $this->cbc);

        $A->onSend = [$B, 'receive'];
        $B->onSend = [$A, 'receive'];

        $A->kexRequest();
        $A->send('Hello!');
        $B->send('Hi!');

        print "\nSetting up MITM:\n\n";

        $A = new ConversationEntity('A', $this->dh, $this->cbc);
        $B = new ConversationEntity('B', $this->dh, $this->cbc);
        $M = new MITM($this->dh, $this->cbc, $A, $B);

        $A->onSend = function(string $data) use($M, $B) {
            $M->sniffA($data, $B);
        };

        $B->onSend = function(string $data) use($M, $A) {
            $M->sniffB($data, $A);
        };

        $A->kexRequest();
        $A->send('Hello!');
        $B->send('Hi!');

        return true;
    }
}
