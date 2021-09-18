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

namespace auth_cnoauth\loginflow;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/cnoauth/lib.php');

/**
 * Login flow for the oauth2 resource owner credentials grant.
 */
class rocreds extends base {
    /**
     * Check for an existing user object.
     * 检查是否存在365用户
     * @param string $o356username
     *
     * @return string If there is an existing user object, return the username associated with it.
     *                If there is no existing user object, return the original username.
     */
    protected function check_objects($o356username) {
        global $DB;

        $user = null;
        // if (auth_cnoauth_is_local_365_installed()) {
        //     $sql = 'SELECT u.username
        //               FROM {local_o365_objects} obj
        //               JOIN {user} u ON u.id = obj.moodleid
        //              WHERE obj.o365name = ? and obj.type = ?';
        //     $params = [$o356username, 'user'];
        //     $user = $DB->get_record_sql($sql, $params);
        // }

        return (!empty($user)) ? $user->username : $o356username;
    }

    /**
     * Provides a hook into the login page.
     *
     * @param object &$frm Form object.
     * @param object &$user User object.
     *
     * @return bool
     */
    public function loginpage_hook(&$frm, &$user) {
        global $DB;

        if (empty($frm)) {
            $frm = data_submitted();
        }
        if (empty($frm)) {
            return true;
        }

        $username = $frm->username;
        $password = $frm->password;
        $auth = 'cnoauth';

        $username = $this->check_objects($username);
        if ($username !== $frm->username) {
            $success = $this->user_login($username, $password);
            if ($success === true) {
                $existinguser = $DB->get_record('user', ['username' => $username]);
                if (!empty($existinguser)) {
                    $user = $existinguser;
                    return true;
                }
            }
        }

        $autoappend = get_config('auth_cnoauth', 'autoappend');
        if (empty($autoappend)) {
            // If we're not doing autoappend, just let things flow naturally.
            return true;
        }

        $existinguser = $DB->get_record('user', ['username' => $username]);
        if (!empty($existinguser)) {
            // We don't want to prevent access to existing accounts.
            return true;
        }

        $username .= $autoappend;
        $success = $this->user_login($username, $password);
        if ($success !== true) {
            // No o365 user, continue normally.
            return false;
        }

        $existinguser = $DB->get_record('user', ['username' => $username]);
        if (!empty($existinguser)) {
            $user = $existinguser;
            return true;
        }

        // The user is authenticated but user creation may be disabled.
        if (!empty($CFG->authpreventaccountcreation)) {
            $failurereason = AUTH_LOGIN_UNAUTHORISED;

            // Trigger login failed event.
            $event = \core\event\user_login_failed::create(array('other' => array('username' => $username,
                    'reason' => $failurereason)));
            $event->trigger();

            error_log('[client '.getremoteaddr()."]  $CFG->wwwroot  Unknown user, can not create new accounts:  $username  ".
                    $_SERVER['HTTP_USER_AGENT']);
            return false;
        }

        $user = create_user_record($username, $password, $auth);
        return true;
    }

    /**
     * This is the primary method that is used by the authenticate_user_login() function in moodlelib.php.
     * 用户登录
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password = null) {
        global $DB;

        $client = $this->get_cnoauthclient();
        $authparams = ['code' => ''];

        $cnoauthusername = $username;
        $cnoauthtoken = $DB->get_records('auth_cnoauth_token', ['username' => $username]);
        if (!empty($cnoauthtoken)) {
            $cnoauthtoken = array_shift($cnoauthtoken);
            if (!empty($cnoauthtoken) && !empty($cnoauthtoken->cnoauthusername)) {
                $cnoauthusername = $cnoauthtoken->cnoauthusername;
            }
        }

        // Make request.
        $tokenparams = $client->rocredsrequest($cnoauthusername, $password);
        if (!empty($tokenparams) && isset($tokenparams['token_type']) && $tokenparams['token_type'] === 'Bearer') {
            list($cnoauthuniqid, $userinfo) = $this->process_userinfo($tokenparams['userinfo']);

            $tokenrec = $DB->get_record('auth_cnoauth_token', ['cnoauthuniqid' => $cnoauthuniqid]);
            if (!empty($tokenrec)) {
                $this->updatetoken($tokenrec->id, $authparams, $tokenparams);
            } else {
                $this->createtoken($cnoauthuniqid, $authparams, $tokenparams, 0);
            }
            return true;
        }
        return false;
    }
}
