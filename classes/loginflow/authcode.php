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

use auth_cnoauth\utils;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/cnoauth/lib.php');

/**
 * Login flow for the oauth2 authorization code grant.
 */
class authcode extends base {
    /**
     * Returns a list of potential IdPs that this authentication plugin supports. Used to provide links on the login page.
     *
     * @param string $wantsurl The relative url fragment the user wants to get to.
     * @return array Array of idps.
     */
    public function loginpage_idp_list($wantsurl) {
        if (empty($this->config->clientid) || empty($this->config->clientsecret)) {
            return [];
        }
        if (empty($this->config->authendpoint) || empty($this->config->tokenendpoint)) {
            return [];
        }

        if (!empty($this->config->customicon)) {
            $icon = new \pix_icon('0/customicon', get_string('pluginname', 'auth_cnoauth'), 'auth_cnoauth');
        } else {
            $icon = (!empty($this->config->icon)) ? $this->config->icon : 'auth_cnoauth:o365';
            $icon = explode(':', $icon);
            if (isset($icon[1])) {
                list($iconcomponent, $iconkey) = $icon;
            } else {
                $iconcomponent = 'auth_cnoauth';
                $iconkey = 'o365';
            }
            $icon = new \pix_icon($iconkey, get_string('pluginname', 'auth_cnoauth'), $iconcomponent);
        }

        return [
            [
                'url' => new \moodle_url('/auth/cnoauth/'),
                'icon' => $icon,
                'name' => $this->config->opname,
            ]
        ];
    }

    /**
     * Get an cnoauth parameter.
     *
     * This is a modification to PARAM_ALPHANUMEXT to add a few additional characters from Base64-variants.
     *
     * @param string $name The name of the parameter.
     * @param string $fallback The fallback value.
     * @return string The parameter value, or fallback.
     */
    protected function getcnoauthparam($name, $fallback = '') {
        $val = optional_param($name, $fallback, PARAM_RAW);
        $val = trim($val);
        $valclean = preg_replace('/[^A-Za-z0-9\_\-\.\+\/\=]/i', '', $val);
        if ($valclean !== $val) {
            utils::debug('Authorization error.', 'authcode::cleancnoauthparam', $name);
            throw new \moodle_exception('errorauthgeneral', 'auth_cnoauth');
        }
        return $valclean;
    }

    /**
     * Handle requests to the redirect URL.
     *
     * @return mixed Determined by loginflow.
     */
    public function handleredirect() {
        global $CFG, $SESSION;

        $state = $this->getcnoauthparam('state');
        $code = $this->getcnoauthparam('code');
        $promptlogin = (bool)optional_param('promptlogin', 0, PARAM_BOOL);
        $promptaconsent = (bool)optional_param('promptaconsent', 0, PARAM_BOOL);
        $justauth = (bool)optional_param('justauth', 0, PARAM_BOOL);
        if (!empty($state)) {
            $requestparams = [
                'state' => $state,
                'code' => $code,
                'error_description' => optional_param('error_description', '', PARAM_TEXT),
            ];
            // Response from OP.
            $this->handleauthresponse($requestparams);
        } else {
            if (isloggedin() && !isguestuser() && empty($justauth) && empty($promptaconsent)) {
                if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                    $urltogo = $SESSION->wantsurl;
                    unset($SESSION->wantsurl);
                } else {
                    $urltogo = new \moodle_url('/');
                }
                redirect($urltogo);
                die();
            }
            // Initial login request.
            $stateparams = ['forceflow' => 'authcode'];
            $extraparams = [];
            if ($promptaconsent === true) {
                $extraparams = ['prompt' => 'admin_consent'];
            }
            if ($justauth === true) {
                $stateparams['justauth'] = true;
            }
            $this->initiateauthrequest($promptlogin, $stateparams, $extraparams);
        }
    }

    /**
     * This is the primary method that is used by the authenticate_user_login() function in moodlelib.php.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password = null) {
        global $CFG, $DB;

        // Check user exists.
        $userfilters = ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id, 'auth' => 'cnoauth'];
        $userexists = $DB->record_exists('user', $userfilters);

        // Check token exists.
        $tokenrec = $DB->get_record('auth_cnoauth_token', ['username' => $username]);
        $code = optional_param('code', null, PARAM_RAW);
        $tokenvalid = (!empty($tokenrec) && !empty($code) && $tokenrec->authcode === $code) ? true : false;
        return ($userexists === true && $tokenvalid === true) ? true : false;
    }

    /**
     * Initiate an authorization request to the configured OP.
     * 
     * @param bool $promptlogin Whether to prompt for login or use existing session.
     * @param array $stateparams Parameters to store as state.
     * @param array $extraparams Additional parameters to send with the cnoauth request.
     */
    public function initiateauthrequest($promptlogin = false, array $stateparams = array(), array $extraparams = array()) {
        $client = $this->get_cnoauthclient();
        $client->authrequest($promptlogin, $stateparams, $extraparams);
    }

    /** ok
     * Handle an authorization request response received from the configured OP.
     * 处理授权请求
     *
     * @param array $authparams Received parameters.
     */
    protected function handleauthresponse(array $authparams) {
        global $DB, $STATEADDITIONALDATA, $USER;

        if (!empty($authparams['error_description'])) {
            utils::debug('Authorization error.', 'authcode::handleauthresponse', $authparams);
            throw new \moodle_exception('errorauthgeneral', 'auth_cnoauth');
        }

        // auth参数没有code
        if (!isset($authparams['code'])) {
            utils::debug('No auth code received.', 'authcode::handleauthresponse', $authparams);
            throw new \moodle_exception('errorauthnoauthcode', 'auth_cnoauth');
        }

        // auth参数没有state
        if (!isset($authparams['state'])) {
            utils::debug('No state received.', 'authcode::handleauthresponse', $authparams);
            throw new \moodle_exception('errorauthunknownstate', 'auth_cnoauth');
        }

        // Validate and expire state.
        // 检查auth_cnoauth_state表中是否存在对应state的记录值
        $staterec = $DB->get_record('auth_cnoauth_state', ['state' => $authparams['state']]);
        if (empty($staterec)) {
            throw new \moodle_exception('errorauthunknownstate', 'auth_cnoauth');
        }
        $orignonce = $staterec->nonce;
        $additionaldata = [];
        if (!empty($staterec->additionaldata)) {
            $additionaldata = @unserialize($staterec->additionaldata);
            if (!is_array($additionaldata)) {
                $additionaldata = [];
            }
        }
        $STATEADDITIONALDATA = $additionaldata;
        $DB->delete_records('auth_cnoauth_state', ['id' => $staterec->id]);

        // Get token from auth code.
        $client = $this->get_cnoauthclient();
        $tokenparams = $client->tokenrequest($authparams['code']);
        if (!isset($tokenparams['user_info'])) {
            throw new \moodle_exception('errorauthnouserinfo', 'auth_cnoauth');
        }

        // Decode and verify userinfo.
        list($cnoauthuniqid, $userinfo) = $this->process_userinfo($tokenparams['user_info'], $orignonce);

        // This is for setting the system API user.
        if (isset($additionaldata['justauth']) && $additionaldata['justauth'] === true) {
            $eventdata = [
                'other' => [
                    'authparams' => $authparams,
                    'tokenparams' => $tokenparams,
                    'statedata' => $additionaldata,
                ]
            ];
            $event = \auth_cnoauth\event\user_authed::create($eventdata);
            $event->trigger();
            return true;
        }

        // user logging in normally with cnoauth.
        $this->handlelogin($cnoauthuniqid, $authparams, $tokenparams, $userinfo);//处理登录
    }

    /** ok
     * Handle a login event. 处理登录事件 
     *
     * @param string $cnoauthuniqid A unique identifier for the user.
     * @param array $authparams Parameters receieved from the auth request.
     * @param array $tokenparams Parameters received from the token request.
     */
    protected function handlelogin($cnoauthuniqid, $authparams, $tokenparams, $userinfo) {
        global $DB;

        $tokenrec = $DB->get_record('auth_cnoauth_token', ['cnoauthuniqid' => $cnoauthuniqid]);
        if (!empty($tokenrec)) {
            // 已存在token记录
            $params = array('cnoauthuniqid'=>$cnoauthuniqid, 'redirecturl'=>'/auth/cnoauth');
            $redirecturl = new \moodle_url('/auth/cnoauth/bindaccount.php', $params);
            if ($tokenrec->userid != 0){
                // tokenrec存在userid值
                $user = $DB->get_record('user', ['id' => $tokenrec->userid]);
                if(empty($user)){
                    // Token is invalid, delete it.
                    $DB->delete_records('auth_cnoauth_token', ['id' => $tokenrec->id]);
                    return $this->handlelogin($cnoauthuniqid, $authparams, $tokenparams, $userinfo);
                }

                complete_user_login($user);  // 用户登录
                redirect(core_login_get_return_url());  // 进入系统
            }else {
                // token表没有记录userid值
                redirect($redirecturl); // 跳转到绑定用户页面
            }

        } else {
            // No existing token, user not connected.没有token的记录
            $tokenrec = $this->createtoken($cnoauthuniqid, $authparams, $tokenparams, 0); 
            return $this->handlelogin($cnoauthuniqid, $authparams, $tokenparams, $userinfo);

        }
    }
}
