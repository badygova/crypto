<?php declare(strict_types = 1);

namespace Cryptopals\Task34;

/**
 * Class PKC7
 * @package Cryptopals\Task34
 */
class PKC7
{
  /**
   * @param string $message
   * @return string
   */
  static function depad(string $message): string
    {
        return substr($message, 0, -static::getPaddingLength($message));
    }

  /**
   * @param string $message
   * @param int $requiredLen
   * @return int
   */
  static function getPaddingLength(string $message, int $requiredLen = 16): int
    {
        $messageLen = strlen($message);
        if (!$messageLen || $messageLen % $requiredLen) {
          throw new \InvalidArgumentException('Invalid message length');
        }

        $padChar = $message[$messageLen - 1];
        $padLen = ord($padChar);
        if (!$padLen || $padLen > $requiredLen) {
          throw new \InvalidArgumentException('Invalid padding');
        }

        $i = $messageLen - 1;
        $limit = $messageLen - $padLen;
        while ($i > $limit) {
          if ($message[--$i] !== $padChar) {
            throw new \InvalidArgumentException('Invalid padding');
          }
        }

        return $padLen;
    }
}
