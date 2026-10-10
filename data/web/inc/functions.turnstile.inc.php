<?php

function turnstile_settings(): array
{
  global $redis;
  $settings = json_decode($redis->get('TURNSTILE_SETTINGS') ?: '{}', true);

  return [
    'site_key' => is_string($settings['site_key'] ?? null) ? trim($settings['site_key']) : '',
    'secret_key' => is_string($settings['secret_key'] ?? null) ? trim($settings['secret_key']) : ''
  ];
}

function turnstile_site_key(): string {
  $settings = turnstile_settings();

  return $settings['site_key'] !== '' && $settings['secret_key'] !== '' ? $settings['site_key'] : '';
}

function turnstile_sogo_web_request(string $uri): bool {
  $segments = [];
  foreach (explode('/', rawurldecode(explode('?', $uri, 2)[0])) as $segment) {
    if ($segment === '..') {
      array_pop($segments);
    }
    elseif ($segment !== '' && $segment !== '.') {
      $segments[] = $segment;
    }
  }
  $path = '/' . implode('/', $segments);

  return preg_match('#^/SOGo(?:/|$)#i', $path) && !preg_match('#^/SOGo/(dav|Microsoft-Server-ActiveSync|WebServerResources)(?:/|$)#i', $path);
}

function turnstile_save(array $data): bool {
  global $redis;
  if (($_SESSION['mailcow_cc_role'] ?? '') !== 'admin' || isset($_SESSION['mailcow_cc_api'])) {
    $_SESSION['return'][] = ['type' => 'danger', 'msg' => 'access_denied'];

    return false;
  }
  if ($GLOBALS['DEMO_MODE']) {
    $_SESSION['return'][] = ['type' => 'danger', 'msg' => 'demo_mode_enabled'];

    return false;
  }
  if (!is_string($data['turnstile_site_key'] ?? null) || !is_string($data['turnstile_secret_key'] ?? null)) {
    $_SESSION['return'][] = ['type' => 'danger', 'msg' => 'access_denied'];

    return false;
  }

  $settings = turnstile_settings();
  $settings['site_key'] = trim($data['turnstile_site_key']);
  $secret = trim($data['turnstile_secret_key']);
  if ($secret !== '') {
    $settings['secret_key'] = $secret;
  }

  if (!empty($data['turnstile_clear'])) {
    $settings = ['site_key' => '', 'secret_key' => ''];
  }

  foreach ($settings as $value) {
    if (strlen($value) > 256 || ($value !== '' && !preg_match('/^[a-zA-Z0-9_-]+$/D', $value))) {
      $_SESSION['return'][] = ['type' => 'danger', 'msg' => 'turnstile_invalid_keys'];

      return false;
    }
  }
  try {
    if (!$redis->set('TURNSTILE_SETTINGS', json_encode($settings))) {
      throw new RuntimeException();
    }
  }
  catch (Exception $e) {
    $_SESSION['return'][] = ['type' => 'danger', 'msg' => 'generic_server_error'];

    return false;
  }
  $_SESSION['return'][] = ['type' => 'success', 'msg' => 'turnstile_saved'];

  return true;
}

function turnstile_verify($token): bool {
  $settings = turnstile_settings();
  if ($settings['site_key'] === '' || $settings['secret_key'] === '') {
    return true;
  }
  $valid = false;
  if (is_string($token) && $token !== '' && strlen($token) <= 2048) {
    $curl = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($curl, [
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => http_build_query(['secret' => $settings['secret_key'], 'response' => $token]),
      CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_TIMEOUT => 10
    ]);
    $response = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);
    $result = is_string($response) ? json_decode($response, true) : null;
    $valid = $status === 200 && is_array($result) && ($result['success'] ?? false) === true && ($result['action'] ?? '') === 'login';
  }
  if (!$valid) {
    $_SESSION['return'][] = ['type' => 'danger', 'msg' => 'turnstile_failed'];
  }
  return $valid;
}
