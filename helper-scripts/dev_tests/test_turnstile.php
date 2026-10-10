<?php
// Run with: php -n -d extension=iconv helper-scripts/dev_tests/test_turnstile.php
// Redis and the HTTP transport are test doubles; no external services are contacted.
if (extension_loaded('curl')) {
  throw new RuntimeException('Run this test with php -n -d extension=iconv so the HTTP transport can be replaced.');
}
foreach (array('CURLOPT_POST', 'CURLOPT_POSTFIELDS', 'CURLOPT_HTTPHEADER', 'CURLOPT_RETURNTRANSFER', 'CURLOPT_CONNECTTIMEOUT', 'CURLOPT_TIMEOUT', 'CURLINFO_HTTP_CODE') as $index => $constant) {
  define($constant, $index);
}
$http_calls = 0;
$http_status = 200;
$http_response = '{"success":true,"action":"login"}';
function curl_init($url) {
  global $http_calls;
  check($url === 'https://challenges.cloudflare.com/turnstile/v0/siteverify', 'Fixed HTTPS verification endpoint');
  $http_calls++;
  return new stdClass();
}
function curl_setopt_array($curl, $options) {
  global $http_options;
  $http_options = $options;
}
function curl_exec($curl) {
  return $GLOBALS['http_response'];
}
function curl_getinfo($curl, $option) {
  return $GLOBALS['http_status'];
}
function curl_close($curl) {}

$checks = 0;
function check($condition, $message) {
  global $checks;
  if (!$condition) {
    throw new RuntimeException($message);
  }
  $checks++;
}
$redis = new class {
  public $value = false;
  public function get($key) {
    check($key === 'TURNSTILE_SETTINGS', 'Settings key');
    return $this->value;
  }
  public function set($key, $value) {
    check($key === 'TURNSTILE_SETTINGS', 'Settings write key');
    $this->value = $value;
    return true;
  }
};
$root = dirname(__DIR__, 2) . '/data/web';
require $root . '/inc/functions.turnstile.inc.php';
$DEMO_MODE = false;
$_SESSION = array();
if (($argv[1] ?? '') === 'fido') {
  $role = $argv[2];
  $valid = $argv[3] === 'valid';
  $redis->value = json_encode(array('site_key' => 'site', 'secret_key' => 'secret'));
  $_POST = array('verify_fido2_login' => 'true', 'token' => 'credential');
  if ($valid) $_POST['cf-turnstile-response'] = 'token';
  $_GET = array();
  $iam_provider = false;
  $fido_called = false;
  function fido2($data) {
    $GLOBALS['fido_called'] = true;
    check($data['token'] === 'credential', 'Passkey credential preserved');
    return false;
  }
  register_shutdown_function(function () use ($valid) {
    check($GLOBALS['fido_called'] === $valid, 'Passkey verification requires Turnstile');
    if (!$valid) check(http_response_code() === 403, 'Missing passkey challenge returns 403');
    print "Passkey guard passed\n";
  });
  include $root . '/inc/triggers.' . $role . '.inc.php';
  throw new RuntimeException('Passkey handler should exit');
}
foreach (array(array(), array('site_key' => 'site'), array('secret_key' => 'secret')) as $settings) {
  $redis->value = json_encode($settings);
  check(turnstile_site_key() === '', 'Incomplete settings hide widget');
  check(turnstile_verify(null), 'Incomplete settings bypass verification');
}
check($http_calls === 0, 'Disabled verification never contacts Cloudflare');

$data = array('turnstile_site_key' => ' site ', 'turnstile_secret_key' => ' secret ');
foreach (array(null, 'user', 'domainadmin') as $role) {
  $_SESSION = array('mailcow_cc_role' => $role);
  check(!turnstile_save($data), 'Only administrators can save settings');
}
$_SESSION = array('mailcow_cc_role' => 'admin', 'mailcow_cc_api' => true);
check(!turnstile_save($data), 'API sessions cannot edit browser-only settings');
unset($_SESSION['mailcow_cc_api']);
$DEMO_MODE = true;
check(!turnstile_save($data), 'Demo mode cannot change keys');
$DEMO_MODE = false;
check(turnstile_save($data), 'Administrator can save settings');
check(turnstile_site_key() === 'site', 'Both credentials enable widget');
check(turnstile_settings()['secret_key'] === 'secret', 'Keys are trimmed');
check(turnstile_save(array('turnstile_site_key' => 'new-site', 'turnstile_secret_key' => '')), 'Blank secret preserves saved secret');
check(turnstile_settings()['secret_key'] === 'secret', 'Existing secret is preserved');
$saved = $redis->value;
check(!turnstile_save(array('turnstile_site_key' => array(), 'turnstile_secret_key' => '')), 'Malformed settings rejected');
check(!turnstile_save(array('turnstile_site_key' => '<script>', 'turnstile_secret_key' => '')), 'Invalid key characters rejected');
check($saved === $redis->value, 'Rejected settings leave storage unchanged');

foreach (array(null, '', array('token'), str_repeat('x', 2049)) as $token) {
  check(!turnstile_verify($token), 'Missing or malformed tokens rejected');
}
check($http_calls === 0, 'Invalid input never contacts Cloudflare');
check(turnstile_verify('valid-token'), 'Successful verification accepted');
parse_str($http_options[CURLOPT_POSTFIELDS], $payload);
check($payload === array('secret' => 'secret', 'response' => 'valid-token'), 'Secret and response sent server-side');
check($http_options[CURLOPT_CONNECTTIMEOUT] === 3 && $http_options[CURLOPT_TIMEOUT] === 10, 'Verification uses bounded timeouts');
foreach (array(false, '', 'not-json', 'null', '[]', '{"success":"true","action":"login"}', '{"success":true}', '{"success":true,"action":"other"}', '{"success":false,"error-codes":["timeout-or-duplicate"]}') as $response) {
  $http_response = $response;
  check(!turnstile_verify('token'), 'Transport errors, malformed responses, wrong actions, expired/reused tokens fail closed');
}
$http_response = '{"success":true,"action":"login"}';
$http_status = 503;
check(!turnstile_verify('token'), 'HTTP failures fail closed');
$http_status = 200;
check(!str_contains(json_encode($_SESSION['return']), 'valid-token'), 'Verification token is not logged');
check(!str_contains(json_encode($_SESSION['return']), 'secret'), 'Secret is not logged');

function check_login($user, $pass, $extra) {
  $GLOBALS['credential_calls'][] = $extra['role'];
  return false;
}
$iam_provider = false;
$credential_calls = array();
foreach (array('admin', 'domainadmin', 'user') as $role) {
  $_POST = array('login_user' => 'example', 'pass_user' => 'password');
  $_GET = array();
  $_SESSION = array();
  include $root . '/inc/triggers.' . $role . '.inc.php';
}
check($credential_calls === array(), 'All password handlers reject a missing challenge before checking credentials');
foreach (array('admin', 'domainadmin', 'user') as $role) {
  $_POST = array('login_user' => 'example', 'pass_user' => 'password', 'cf-turnstile-response' => 'token');
  include $root . '/inc/triggers.' . $role . '.inc.php';
}
check($credential_calls === array('admin', 'domain_admin', 'user'), 'All password handlers continue after successful verification');
foreach (array('admin', 'domainadmin', 'user') as $role) {
  foreach (array('valid', 'missing') as $token) {
    $command = escapeshellarg(PHP_BINARY) . ' -n -d extension=iconv ' . escapeshellarg(__FILE__) . ' fido ' . $role . ' ' . $token;
    $output = array();
    exec($command, $output, $status);
    check($status === 0 && in_array('Passkey guard passed', $output), 'Passkey handler: ' . $role . ' / ' . $token);
  }
}
foreach (array('/SOGo', '/SOGo/', '/SOGo/so/', '/SOGo/connect', '/SOGo/so/user', '/SOGo/dav/../so/user', '/SOGo/dav/%2e%2e/so/user', '//SOGo//so/user', '/%53OGo/so/user') as $uri) {
  check((bool)turnstile_sogo_web_request($uri), 'Webmail path requires protected login: ' . $uri);
}
foreach (array('/SOGo/dav', '/SOGo/dav/user', '/SOGo/%64av/user', '/SOGo/Microsoft-Server-ActiveSync', '/Microsoft-Server-ActiveSync', '/SOGo/WebServerResources/test.js') as $uri) {
  check(!turnstile_sogo_web_request($uri), 'Protocol/static access is unchanged: ' . $uri);
}
$_SESSION = array('mailcow_cc_role' => 'admin');
check(turnstile_save($data + array('turnstile_clear' => '1')), 'Settings can be cleared');
check(turnstile_settings() === array('site_key' => '', 'secret_key' => ''), 'Disable removes both credentials');
check(turnstile_site_key() === '' && turnstile_verify(null), 'Disabling restores previous login behavior');

require $root . '/inc/lib/vendor/autoload.php';
$twig = new Twig\Environment(new Twig\Loader\FilesystemLoader($root . '/templates'));
$twig->addFunction(new Twig\TwigFunction('query_string', fn($params = array()) => ''));
$twig->addFunction(new Twig\TwigFunction('is_uri', fn($uri, $where = null) => false));
$twig->addFilter(new Twig\TwigFilter('rot13', 'str_rot13'));
$twig->addFilter(new Twig\TwigFilter('base64_encode', 'base64_encode'));
$twig->addFilter(new Twig\TwigFilter('formatBytes', fn($value) => $value));
$lang = json_decode(file_get_contents($root . '/lang/lang.en-gb.json'), true, 512, JSON_THROW_ON_ERROR);
$context = array('lang' => $lang, 'turnstile_site_key' => 'public-site', 'custom_login' => array('force_sso' => 0));
foreach (array('user_index.twig', 'admin_index.twig', 'domainadmin_index.twig', 'turnstile_gate.twig') as $template) {
  $html = $twig->render($template, $context);
  check(substr_count($html, 'challenges.cloudflare.com/turnstile/v0/api.js') === 1, $template . ' loads one widget script');
  check(str_contains($html, 'data-sitekey="public-site"'), $template . ' renders public key');
  $html = $twig->render($template, array_merge($context, array('turnstile_site_key' => '')));
  check(!str_contains($html, 'challenges.cloudflare.com'), $template . ' loads no external script when disabled');
  check(!str_contains($html, 'class="cf-turnstile"'), $template . ' hides widget when disabled');
}
$html = $twig->render('admin/tab-config-turnstile.twig', array('lang' => $lang, 'turnstile_settings' => array('site_key' => 'public-site', 'has_secret' => true)));
check(str_contains($html, 'name="turnstile_secret_key"'), 'Dedicated settings include a secret input');
check(!str_contains($html, 'value="secret"'), 'Stored secret is not rendered');
$twig->load('admin.twig');
print "Turnstile tests passed ($checks checks).\n";