<?php declare(strict_types = 1);

namespace Cryptopals\Task35;

use AES\CBC;
use AES\Key;
use Cryptopals\Task34\PKC7;
use Cryptopals\Task33\DH;

/**
 * Class ConversationEntity
 * @package Cryptopals\Task35
 */
class ConversationEntity
{
    private $name;
    private $dh;

    private $priv;
    private $pub;
    private $shared;

    public $onSend;

    protected $cbc;
    protected $pkcs7;

  /**
   * ConversationEntity constructor.
   * @param string $name
   * @param DH $dh
   */
  function __construct(string $name, DH $dh)
    {
        $this->name = $name;
        $this->dh = $dh;

        $this->cbc = new CBC;
        $this->pkcs7 = new PKC7;

        $this->priv = $this->dh->generatePrivate();
    }

  /**
   *
   */
  function groupNeg()
    {
        print "{$this->name}: p/g neg\n";

        $obj = new \stdClass();
        $obj->msg = 'neg';
        $obj->p = $this->dh->p();
        $obj->g = $this->dh->g();

        $func = $this->onSend;
        $func(json_encode($obj));
    }

  /**
   *
   */
  function groupAck()
    {
        print "{$this->name}: p/g ack\n";

        $obj = new \stdClass();
        $obj->msg = 'ack';
        $obj->p = $this->dh->p();
        $obj->g = $this->dh->g();

        $func = $this->onSend;
        $func(json_encode($obj));
    }

  /**
   *
   */
  function sendPub()
    {
        print "{$this->name}: send pub\n";

        $this->pub = $this->dh->generatePublic($this->priv);

        $obj = new \stdClass();
        $obj->msg = 'pub';
        $obj->pub = gmp_strval($this->pub, 16);

        $func = $this->onSend;
        $func(json_encode($obj));
    }

  /**
   * @param string $data
   * @throws \Exception
   */
  function send(string $data)
    {
        $obj = new \stdClass();
        $obj->msg = 'dat';
        $obj->data = $data;

        $data = json_encode($obj);

        if (!is_null($this->shared)) {
            $key = new Key(substr(sha1($this->shared, true), 0, 16));
            $iv = random_bytes(16);

            $data = $iv . $this->cbc->encrypt($key, $iv, $this->pkcs7->pad($data));
        }

        $dataLen = strlen($data);

        print "{$this->name}: sending $dataLen bytes\n";

        $func = $this->onSend;
        $func($data);
    }

  /**
   * @param string $data
   */
  function receive(string $data)
    {
        $dataLen = strlen($data);
        print "{$this->name}: received $dataLen bytes\n";

        if (!is_null($this->shared)) {
            $key = new Key(substr(sha1($this->shared, true), 0, 16));
            $iv = substr($data, 0, 16);

            $data = $this->cbc->decrypt($key, $iv, substr($data, 16));
            $data = $this->pkcs7->depad($data);
        }

        $obj = json_decode($data);

        switch ($obj->msg) {
            case 'neg':
                print "{$this->name}: received group negotiation\n";
                $this->dh->g($obj->g);
                $this->groupAck();
                $this->sendPub();
                break;
            case 'ack':
                print "{$this->name}: received group acknowledgement\n";
                $this->dh->g($obj->g);
                $this->sendPub();
                break;
            case 'pub':
                print "{$this->name}: received public key\n";
                $this->shared = gmp_strval($this->dh->generateShared($this->priv, gmp_init($obj->pub, 16)), 16);
                break;
            case 'dat':
                print "{$this->name}: received data: {$obj->data}\n";
                break;
            default:
                print "{$this->name}: unknown message\n";
        }
    }
}
