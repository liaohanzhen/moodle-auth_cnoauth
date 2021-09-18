<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Admin page to cleanup cnoauth tokens.
 *
 * @package auth_cnoauth
 * @author Martin Liao <liaohanzhen@163.com>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2021
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->dirroot . '/auth/cnoauth/lib.php');

require_login();

$context = context_system::instance();
$pageurl = new moodle_url('/auth/cnoauth/cleanupcnoauthtokens.php');

require_capability('moodle/site:config', $context);

$PAGE->set_url($pageurl);
$PAGE->set_context($context);
$PAGE->set_pagelayout('admin');
$PAGE->set_heading(get_string('cleanup_cnoauth_tokens', 'auth_cnoauth'));
$PAGE->set_title(get_string('cleanup_cnoauth_tokens', 'auth_cnoauth'));

$PAGE->navbar->add(get_string('administrationsite'), new moodle_url('/admin/search.php'));
$PAGE->navbar->add(get_string('plugins', 'admin'), new moodle_url('/admin/category.php', ['category' => 'modules']));
$PAGE->navbar->add(get_string('authentication', 'admin'), new moodle_url('/admin/category.php', ['category' => 'authsettings']));
$PAGE->navbar->add(get_string('pluginname', 'auth_cnoauth'), new moodle_url('/admin/settings.php', ['section' => 'authsettingcnoauth']));
$PAGE->navbar->add(get_string('cleanup_cnoauth_tokens', 'auth_cnoauth'));

$emptyuseruserinfos = auth_cnoauth_get_tokens_with_empty_ids();
$mismatchedtokens = auth_cnoauth_get_tokens_with_mismatched_usernames();

$tokenstoclean = $emptyuseruserinfos + $mismatchedtokens;

uasort($tokenstoclean, function($a, $b) {
    return strcmp($a->cnoauthusername, $b->cnoauthusername);
});

$deletetokenid = optional_param('id', 0, PARAM_INT);
if ($deletetokenid) {
    if (array_key_exists($deletetokenid, $tokenstoclean)) {
        auth_cnoauth_delete_token($deletetokenid);

        redirect($pageurl, get_string('token_deleted', 'auth_cnoauth'));
    }
}

if ($tokenstoclean) {
    $table = new html_table();
    $table->head = [
        get_string('table_token_id', 'auth_cnoauth'),
        get_string('table_cnoauth_username', 'auth_cnoauth'),
        get_string('table_token_unique_id', 'auth_cnoauth'),
        get_string('table_matching_status', 'auth_cnoauth'),
        get_string('table_matching_details', 'auth_cnoauth'),
        get_string('table_action', 'auth_cnoauth'),
    ];
    $table->colclasses = [
        'leftalign',
        'leftalign',
        'leftalign',
        'leftalign',
        'leftalign',
        'centeralign',
    ];
    $table->attributes['class'] = 'admintable generaltable';
    $table->id = 'cleanupcnoauthtokens';
    $table->data = [];
    foreach ($tokenstoclean as $item) {
        $table->data[] = [
            $item->id,
            $item->cnoauthusername,
            $item->cnoauthuniqueid,
            $item->matchingstatus,
            $item->details,
            $item->action,
        ];
    }
}

echo $OUTPUT->header();

if ($tokenstoclean) {
    echo html_writer::table($table);
} else {
    echo html_writer::span(get_string('no_token_to_cleanup', 'auth_cnoauth'));
}

echo $OUTPUT->footer();
