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

namespace auth_cnoauth;

/**
 * General purpose utility class.
 */
class utils {

    /**
     * Process an cnoauth JSON response.
     * 检查返回的token数据是否有效
     * 
     * @param string $response The received JSON.
     * @return array The parsed JSON.
     */
    public static function process_json_response($response, array $expectedstructure = array()) {
        $backtrace = debug_backtrace(0);
        $callingclass = (isset($backtrace[1]['class'])) ? $backtrace[1]['class'] : '?';
        $callingfunc = (isset($backtrace[1]['function'])) ? $backtrace[1]['function'] : '?';
        $callingline = (isset($backtrace[0]['line'])) ? $backtrace[0]['line'] : '?';
        $caller = $callingclass.'::'.$callingfunc.':'.$callingline;

        $result = @json_decode($response, true);
        if (empty($result) || !is_array($result)) {
            self::debug('Bad response received', $caller, $response);
            throw new \moodle_exception('errorcnoauthcall', 'auth_cnoauth');
        }

        if (isset($result['error'])) {
            $errmsg = 'Error response received.';
            self::debug($errmsg, $caller, $result);
            if (isset($result['error_description'])) {
                throw new \moodle_exception('errorcnoauthcall_message', 'auth_cnoauth', '', $result['error_description']);
            } else {
                throw new \moodle_exception('errorcnoauthcall', 'auth_cnoauth');
            }
        }

        foreach ($expectedstructure as $key => $val) {
            if (!isset($result[$key])) {
                $errmsg = 'Invalid structure received. No "'.$key.'"';
                self::debug($errmsg, $caller, $result);
                throw new \moodle_exception('errorcnoauthcall', 'auth_cnoauth');
            }

            if ($val !== null && $result[$key] !== $val) {
                $strreceivedval = self::tostring($result[$key]);
                $strval = self::tostring($val);
                $errmsg = 'Invalid structure received. Invalid "'.$key.'". Received "'.$strreceivedval.'", expected "'.$strval.'"';
                self::debug($errmsg, $caller, $result);
                throw new \moodle_exception('errorcnoauthcall', 'auth_cnoauth');
            }
        }
        return $result;
    }

    /**
     * Convert any value into a debuggable string.
     *
     * @param mixed $val The variable to convert.
     * @return string A string representation.
     */
    public static function tostring($val) {
        if (is_scalar($val)) {
            if (is_bool($val)) {
                return '(bool)'.(string)(int)$val;
            } else {
                return '('.gettype($val).')'.(string)$val;
            }
        } else if (is_null($val)) {
            return '(null)';
        } else if ($val instanceof \Exception) {
            $valinfo = [
                'file' => $val->getFile(),
                'line' => $val->getLine(),
                'message' => $val->getMessage(),
            ];
            if ($val instanceof \moodle_exception) {
                $valinfo['debuginfo'] = $val->debuginfo;
                $valinfo['errorcode'] = $val->errorcode;
                $valinfo['module'] = $val->module;
            }
            return print_r($valinfo, true);
        } else {
            return print_r($val, true);
        }
    }

    /**
     * Record a debug message.
     *
     * @param string $message The debug message to log.
     */
    public static function debug($message, $where = '', $debugdata = null) {
        $debugmode = (bool)get_config('auth_cnoauth', 'debugmode');
        if ($debugmode === true) {
            $fullmessage = (!empty($where)) ? $where : 'Unknown function';
            $fullmessage .= ': '.$message;
            $fullmessage .= ' Data: '.static::tostring($debugdata);
            $event = \auth_cnoauth\event\action_failed::create(['other' => $fullmessage]);
            $event->trigger();
        }
    }

    /**
     * Get the redirect URL that should be set in the identity provider
     *
     * @return string The redirect URL.
     */
    public static function get_redirecturl() {
        global $CFG;
        $wwwroot = (!empty($CFG->loginhttps)) ? str_replace('http://', 'https://', $CFG->wwwroot) : $CFG->wwwroot;
        return $wwwroot.'/auth/cnoauth/';
    }
}