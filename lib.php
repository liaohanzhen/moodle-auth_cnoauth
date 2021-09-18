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
 * @package auth_cnoauth
 * @author Martin Liao <liaohanzhen@163.com>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2021
 */

defined('MOODLE_INTERNAL') || die();

function auth_cnoauth_initialize_customicon($filefullname) {
    global $CFG;

    $file = get_config('auth_cnoauth', 'customicon');
    $systemcontext = \context_system::instance();
    $fullpath = "/{$systemcontext->id}/auth_cnoauth/customicon/0{$file}";

    $fs = get_file_storage();
    if (!$file = $fs->get_file_by_hash(sha1($fullpath)) or $file->is_directory()) {
        return false;
    }
    $pixpluginsdir = 'pix_plugins/auth/cnoauth/0';
    $pixpluginsdirparts = explode('/', $pixpluginsdir);
    $curdir = $CFG->dataroot;
    foreach ($pixpluginsdirparts as $dir) {
        $curdir .= '/' . $dir;
        if (!file_exists($curdir)) {
            mkdir($curdir);
        }
    }

    if (file_exists($CFG->dataroot . '/pix_plugins/auth/cnoauth/0')) {
        $file->copy_content_to($CFG->dataroot . '/pix_plugins/auth/cnoauth/0/customicon.jpg');
        theme_reset_all_caches();
    }
}

/**
 * Check for connection abilities.
 *
 * @param int $userid Moodle user id to check permissions for.
 * @param string $mode Mode to check
 *                     'connect' to check for connect specific capability
 *                     'disconnect' to check for disconnect capability.
 *                     'both' to check for disconnect and connect capability.
 * @param boolean $require Use require_capability rather than has_capability.
 *
 * @return boolean True if has capability.
 */
function auth_cnoauth_connectioncapability($userid, $mode = 'connect', $require = false) {
    $check = 'has_capability';
    if ($require) {
        // If requiring the capability and user has manageconnection than checking connect and disconnect is not needed.
        $check = 'require_capability';
        if (has_capability('auth/cnoauth:manageconnection', \context_user::instance($userid), $userid)) {
            return true;
        }
    } else if ($check('auth/cnoauth:manageconnection', \context_user::instance($userid), $userid)) {
        return true;
    }

    $result = false;
    switch ($mode) {
        case "connect":
            $result = $check('auth/cnoauth:manageconnectionconnect', \context_user::instance($userid), $userid);
            break;
        case "disconnect":
            $result = $check('auth/cnoauth:manageconnectiondisconnect', \context_user::instance($userid), $userid);
            break;
        case "both":
            $result = $check('auth/cnoauth:manageconnectionconnect', \context_user::instance($userid), $userid);
            $result = $result && $check('auth/cnoauth:manageconnectiondisconnect', \context_user::instance($userid), $userid);
    }
    if ($require) {
        return true;
    }

    return $result;
}


/**
 * Return details of all auth_cnoauth tokens having empty Moodle user IDs.
 * 获得没有对应用户ID的token，根据username匹配
 * @return array
 */
function auth_cnoauth_get_tokens_with_empty_ids() {
    global $DB;

    $emptyuseruserinfos = [];

    $records = $DB->get_records('auth_cnoauth_token', ['userid' => '0']);

    foreach ($records as $record) {
        $item = new stdClass();
        $item->id = $record->id;
        $item->cnoauthusername = $record->cnoauthusername;
        $item->moodleusername = $record->username;
        $item->userid = 0;
        $item->cnoauthuniqueid = $record->cnoauthuniqid;
        $item->matchingstatus = get_string('unmatched', 'auth_cnoauth');
        $item->details = get_string('na', 'auth_cnoauth');
        $deletetokenurl = new moodle_url('/auth/cnoauth/cleanupcnoauthtokens.php', ['id' => $record->id]);
        $item->action = html_writer::link($deletetokenurl, get_string('delete_token', 'auth_cnoauth'));

        $emptyuseruserinfos[$record->id] = $item;
    }

    return $emptyuseruserinfos;
}

/**
 * Return details of all auth_cnoauth tokens with matching Moodle user IDs, but mismatched usernames.
 * 获得不匹配的用户
 * @return array
 */
function auth_cnoauth_get_tokens_with_mismatched_usernames() {
    global $DB;

    $mismatchedtokens = [];

    $sql = 'SELECT tok.id AS id, tok.userid AS tokenuserid, tok.username AS tokenusernmae, tok.cnoauthusername AS cnoauthusername,
                   tok.cnoauthuniqid as cnoauthuniqid, u.id AS muserid, u.username AS musername
              FROM {auth_cnoauth_token} tok
              JOIN {user} u ON u.id = tok.userid
             WHERE tok.userid != 0
               AND u.username != tok.username';
    $records = $DB->get_recordset_sql($sql);
    foreach ($records as $record) {
        $item = new stdClass();
        $item->id = $record->id;
        $item->cnoauthusername = $record->cnoauthusername;
        $item->userid = $record->muserid;
        $item->cnoauthuniqueid = $record->cnoauthuniqid;
        $item->matchingstatus = get_string('mismatched', 'auth_cnoauth');
        $item->details = get_string('mismatched_details', 'auth_cnoauth',
            ['tokenusername' => $record->tokenusername, 'moodleusername' => $record->musername]);
        $deletetokenurl = new moodle_url('/auth/cnoauth/cleanupcnoauthtokens.php', ['id' => $record->id]);
        $item->action = html_writer::link($deletetokenurl, get_string('delete_token_and_reference', 'auth_cnoauth'));

        $mismatchedtokens[$record->id] = $item;
    }

    return $mismatchedtokens;
}

/**
 * Delete the auth_cnoauth token with the ID.
 * 删除token
 * @param int $tokenid
 */
function auth_cnoauth_delete_token(int $tokenid) {
    global $DB;

    $DB->delete_records('auth_cnoauth_token', ['id' => $tokenid]);
}
