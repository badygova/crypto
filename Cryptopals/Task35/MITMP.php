<?php declare(strict_types = 1);

namespace Cryptopals\Task35;

use AES\Key;
use Cryptopals\Task34\PKC7;

/**
 * Class MITMP
 * g = p
 * @package Cryptopals\Task35
 */
class MITMP extends MITM
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
                $obj->g = $obj->p;
                $data = json_encode($obj);
            }
            else {
                print "M: sniffed: $data\n";
            }
        }
        else {
            $key = new Key(substr(sha1('0', true), 0, 16));
            $iv = substr($data, 0, 16);

            $message = $this->cbc->decrypt($key, $iv, substr($data, 16));
            $message = PKC7::depad($message);
            print "M: sniffed: $message\n";
        }

        return $data;
    }
}
