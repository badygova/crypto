#!/bin/env php
<?php declare(strict_types = 1);

namespace Cryptopals;

use Auryn\InjectionException;
use Auryn\Injector;

require 'vendor/autoload.php';

if ($argc < 2) {
    print basename($argv[0]) . " <ex_id>\n";
    exit(1);
}

$ex = [1 =>
    'Implement Diffie-Hellman',
    'Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection',
    'Implement DH with negotiated groups, and break with malicious "g" parameters',
];

$exId = (int)$argv[1];

$exName = $ex[$exId] ?? null;

$injector = new Injector();
$solutionClass = "\\Cryptopals\\Task{$exId}\\Main";

try {
    /** @var \Cryptopals\Solution $solution */
    $solution = $injector->make($solutionClass);
}
catch (InjectionException $e) {
    print "Could not instantiate solution for Challenge {$exId}\n";
    $message = $e->getMessage();
    print "{$message}\n";
    exit(1);
}

print "Task {$exId}: {$exName}\n";
print str_repeat('#', 80) . "\n";

$result = $solution->execute();

print str_repeat('#', 80) . "\n";
print ($result ? 'Success' : 'Failure') . "\n";
