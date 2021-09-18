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
 * 
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2021
 */

namespace auth_cnoauth\loginflow;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/cnoauth/lib.php');

class base {
    /** @var object Plugin config. */
    public $config;

    /** @var \auth_cnoauth\httpclientinterface An HTTP client to use. */
    protected $httpclient;

    public function __construct() {
        $default = [
            'opname' => get_string('pluginname', 'auth_cnoauth')
        ];
        $storedconfig = (array)get_config('auth_cnoauth');
        $forcedconfig = [
            'field_updatelocal_idnumber' => 'oncreate',
            'field_lock_idnumber' => 'unlocked',
            'field_updatelocal_lang' => 'oncreate',
            'field_lock_lang' => 'unlocked',
            'field_updatelocal_firstname' => 'oncreate',
            'field_lock_firstname' => 'unlocked',
            'field_updatelocal_lastname' => 'oncreate',
            'field_lock_lastname' => 'unlocked',
            'field_updatelocal_email' => 'oncreate',
            'field_lock_email' => 'unlocked',
        ];

        $this->config = (object)array_merge($default, $storedconfig, $forcedconfig);
    }

    /**
     * Returns a list of potential IdPs that this authentication plugin supports. Used to provide links on the login page.
     *
     * @param string $wantsurl The relative url fragment the user wants to get to.
     * @return array Array of idps.
     */
    public function loginpage_idp_list($wantsurl) {
        return [];
    }

    /**
     * This is the primary method that is used by the authenticate_user_login() function in moodlelib.php.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password = null) {
        return false;
    }

    /**
     * Provides a hook into the login page.
     *
     * @param object &$frm Form object.
     * @param object &$user User object.
     */
    public function loginpage_hook(&$frm, &$user) {
        return true;
    }

    /**
     * Read user information from external database and returns it as array().
     *
     * @param string $username username
     * @return mixed array with no magic quotes or false on error
     */
    public function get_userinfo($username) {
        global $DB;

        $tokenrec = $DB->get_record('auth_cnoauth_token', ['username' => $username]);
        if (empty($tokenrec)) {
            return false;
        }

        if ($DB->record_exists('user', ['username' => $username])) {
            $eventtype = 'login';
        } else {
            $eventtype = 'create';
        }

        $userinfo = [];

        $user_info = json_decode($tokenrec->userinfo);

        $firstname = $user_info['given_name'];
        if (!empty($firstname)) {
            $userinfo['firstname'] = $firstname;
        }

        $lastname = $user_info['family_name'];
        if (!empty($lastname)) {
            $userinfo['lastname'] = $lastname;
        }

        $email = $user_info['email'];
        if (!empty($email)) {
            $userinfo['email'] = $email;
        } else {
            $upn = $user_info['upn'];
            if (!empty($upn)) {
                $aademailvalidateresult = filter_var($upn, FILTER_VALIDATE_EMAIL);
                if (!empty($aademailvalidateresult)) {
                    $userinfo['email'] = $aademailvalidateresult;
                }
            }
        }

        return $userinfo;
    }

    /**
     * Set an HTTP client to use.
     *
     * @param auth_cnoauthhttpclientinterface $httpclient [description]
     */
    public function set_httpclient(\auth_cnoauth\httpclientinterface $httpclient) {
        $this->httpclient = $httpclient;
    }

    /**
     * Handle requests to the redirect URL.
     *
     * @return mixed Determined by loginflow.
     */
    public function handleredirect() {

    }

    /**
     * Construct the CN OpenID Connect client.
     *
     * @return \auth_cnoauth\cnoauthclient The constructed client.
     */
    protected function get_cnoauthclient() {
        global $CFG;
        if (empty($this->httpclient) || !($this->httpclient instanceof \auth_cnoauth\httpclientinterface)) {
            $this->httpclient = new \auth_cnoauth\httpclient();
        }
        if (empty($this->config->clientid) || empty($this->config->clientsecret)) {
            throw new \moodle_exception('errorauthnocreds', 'auth_cnoauth');
        }
        if (empty($this->config->authendpoint) || empty($this->config->tokenendpoint) || empty($this->config->userinfoendpoint)) {
            throw new \moodle_exception('errorauthnoendpoints', 'auth_cnoauth');
        }
        

        $clientid = (isset($this->config->clientid)) ? $this->config->clientid : null;
        $clientsecret = (isset($this->config->clientsecret)) ? $this->config->clientsecret : null;
        $redirecturi = (!empty($CFG->loginhttps)) ? str_replace('http://', 'https://', $CFG->wwwroot) : $CFG->wwwroot;
        $redirecturi .= '/auth/cnoauth/';
        $scope = (isset($this->config->cnoauthscope)) ? $this->config->cnoauthscope : null;

        $client = new \auth_cnoauth\cnoauthclient($this->httpclient);
        $client->setcreds($clientid, $clientsecret, $redirecturi, $tokenresource, $scope);

        $authendpoint = $this->config->authendpoint;
        $tokenendpoint = $this->config->tokenendpoint;
        $userinfoendpoint = $this->config->userinfoendpoint;
        
        $client->setendpoints(['auth' => $authendpoint, 'token' => $tokenendpoint, 'userinfo' => $userinfoendpoint]);
        return $client;
    }

    /**
     * Process an userinfo, extract uniqid and construct jwt object.
     *
     * @param string $userinfo Encoded user info.
     * @param string $orignonce Original nonce to validate received nonce against.
     * @return array List of cnoauthuniqid and constructed userinfo jwt.
     */
    protected function process_userinfo($userinfo, $orignonce = '') {
        // Decode and verify userinfo.

        $openid = $userinfo['openid'];
        if (empty($openid)) {
            \auth_cnoauth\utils::debug('Invalid userinfo', 'base::process_userinfo', $userinfo);
            throw new \moodle_exception('errorauthinvaliduserinfo', 'auth_cnoauth');
        }

        // //检查提交的nonce和返回的是否一致
        // $receivednonce = $userinfo->claim('nonce');  
        // // if (!empty($orignonce) && (empty($receivednonce) || $receivednonce !== $orignonce))
        // if (!empty($orignonce) && (empty($receivednonce))) {
        //     \auth_cnoauth\utils::debug('Invalid nonce', 'base::process_userinfo', $userinfo);
        //     throw new \moodle_exception('errorauthinvaliduserinfo', 'auth_cnoauth');
        // }

        // 如果没有获得unionid，则将openid作为唯一识别.
        $cnoauthuniqid = $userinfo['unionid'];
        if (empty($cnoauthuniqid)) {
            $cnoauthuniqid = $openid;
        }
        return [$cnoauthuniqid, $userinfo];
    }

    /**
     * Create a token for a user, thus linking a Moodle user to an CN OpenID Connect user.
     * 创建token用于链接用户
     * 
     * @param string $cnoauthuniqid A unique identifier for the user.
     * @param array $authparams Parameters receieved from the auth request.
     * @param array $tokenparams Parameters received from the token request.
     * @param int $userid
     * @return \stdClass The created token database record.
     */
    protected function createtoken($cnoauthuniqid, $authparams, $tokenparams, $userid = 0) {
        global $DB;

        $tokenrec = new \stdClass;
        $tokenrec->cnoauthuniqid = $cnoauthuniqid;
        $tokenrec->userid = $userid;
        $tokenrec->scope = !empty($tokenparams['scope']) ? $tokenparams['scope'] : $this->config->cnoauthscope;
        $tokenrec->authcode = $authparams['code'];
        $tokenrec->token = $tokenparams['access_token'];
        if (!empty($tokenparams['expires_on'])) {
            $tokenrec->expiry = $tokenparams['expires_on'];
        } else if (isset($tokenparams['expires_in'])) {
            $tokenrec->expiry = time() + $tokenparams['expires_in'];
        } else {
            $tokenrec->expiry = time() + DAYSECS;
        }
        $tokenrec->refreshtoken = !empty($tokenparams['refresh_token']) ? $tokenparams['refresh_token'] : ''; // TBD?
        $tokenrec->userinfo = json_encode($tokenparams['user_info']);
        $tokenrec->id = $DB->insert_record('auth_cnoauth_token', $tokenrec);
        return $tokenrec;
    }

    /**
     * Update a token with a new auth code and access token data.
     * 更新token
     * @param int $tokenid The database record ID of the token to update.
     * @param array $authparams Parameters receieved from the auth request.
     * @param array $tokenparams Parameters received from the token request.
     */
    protected function updatetoken($tokenid, $authparams, $tokenparams) {
        global $DB;
        $tokenrec = new \stdClass;
        $tokenrec->id = $tokenid;
        $tokenrec->authcode = $authparams['code'];
        $tokenrec->token = $tokenparams['access_token'];
        if (!empty($tokenparams['expires_on'])) {
            $tokenrec->expiry = $tokenparams['expires_on'];
        } else if (isset($tokenparams['expires_in'])) {
            $tokenrec->expiry = time() + $tokenparams['expires_in'];
        } else {
            $tokenrec->expiry = time() + DAYSECS;
        }
        $tokenrec->refreshtoken = !empty($tokenparams['refresh_token']) ? $tokenparams['refresh_token'] : ''; // TBD?
        $tokenrec->userinfo = $tokenparams['userinfo'];
        $DB->update_record('auth_cnoauth_token', $tokenrec);
    }
}
