<?php
if (turnstile_site_key() !== '' && (!isset($_POST['cf-turnstile-response']) || !turnstile_verify($_POST['cf-turnstile-response']))) {
  require $_SERVER['DOCUMENT_ROOT'] . '/inc/header.inc.php';
  $template = 'turnstile_gate.twig';
  $template_data = [];
  require $_SERVER['DOCUMENT_ROOT'] . '/inc/footer.inc.php';
  exit;
}