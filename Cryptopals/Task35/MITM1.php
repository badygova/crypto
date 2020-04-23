<?php declare(strict_types = 1);

namespace Cryptopals\Task35;

use AES\Key;
use Cryptopals\Task34\PKC7;

/**
 * Class MITM1
 * g = 1
 * @package Cryptopals\Task35
 */
class MITM1 extends MITM
{
  /**
   * @param string $data
   * @return string
   */
  function sniffData(string $data): string
    {
        $obj = json_decode($data);

        if (is_object($obj)) {
            if (is_object($obj) && ($obj->msg === 'neg' || $obj->msg === 'ack')) {
                print "M: manipulating g\n";
                $obj->g = '1';
                $data = json_encode($obj);
            }
            else {
                print "M: sniffed: $data\n";
            }
        }
        else {
            $key = new Key(substr(sha1('1', true), 0, 16));
            $iv = substr($data, 0, 16);

            $message = $this->cbc->decrypt($key, $iv, substr($data, 16));
            $message = PKCS7::depad($message);

            print "M: sniffed: $message\n";
        }

        return $data;
    }
}
