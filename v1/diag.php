<?php
header('Content-Type: text/plain');
echo "PHP_VERSION: " . PHP_VERSION . "\n";
echo "PHP_SAPI: " . PHP_SAPI . "\n";
echo "Sodium ext: " . (extension_loaded('sodium') ? 'yes' : 'NO') . "\n";
echo "Argon2id const: " . (defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13') ? 'yes' : 'NO') . "\n";
echo "Session save path: " . ini_get('session.save_path') . "\n";
echo "Keys readable: " . (is_readable('/home/beardedviking/secure_mycitadel.lol/keys') ? 'yes' : 'no') . "\n";
echo "Logs writable: " . (is_writable('/home/beardedviking/secure_mycitadel.lol/logs') ? 'yes' : 'no') . "\n";
echo "Sessions writable: " . (is_writable('/home/beardedviking/secure_mycitadel.lol/sessions') ? 'yes' : 'no') . "\n";
