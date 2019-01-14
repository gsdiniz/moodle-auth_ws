<?php

define('CLI_SCRIPT', true);

require(__DIR__.'/../../../config.php');
require_once("$CFG->libdir/clilib.php");

if (!is_enabled_auth('ws')) {
    cli_error('auth_ws plugin is disabled, synchronisation stopped', 2);
}

get_auth_plugin('ws')->map_users();
