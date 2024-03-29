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
 * Plugin settings.
 *
 * @package auth_cnoauth
 * @author Martin Liao <liaohanzhen@163.com>
 * 
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2021
 */

defined('MOODLE_INTERNAL') || die();

use auth_cnoauth\adminsetting\auth_cnoauth_admin_setting_iconselect;
use auth_cnoauth\adminsetting\auth_cnoauth_admin_setting_loginflow;
use auth_cnoauth\adminsetting\auth_cnoauth_admin_setting_redirecturi;
use auth_cnoauth\adminsetting\auth_cnoauth_admin_setting_label;

require_once($CFG->dirroot . '/auth/cnoauth/lib.php');

$configkey = new lang_string('cfg_opname_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_opname_desc', 'auth_cnoauth');
$configdefault = new lang_string('pluginname', 'auth_cnoauth');
$settings->add(new admin_setting_configtext('auth_cnoauth/opname', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_clientid_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_clientid_desc', 'auth_cnoauth');
$settings->add(new admin_setting_configtext('auth_cnoauth/clientid', $configkey, $configdesc, '', PARAM_TEXT));

$configkey = new lang_string('cfg_clientsecret_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_clientsecret_desc', 'auth_cnoauth');
$settings->add(new admin_setting_configtext('auth_cnoauth/clientsecret', $configkey, $configdesc, '', PARAM_TEXT));

$configkey = new lang_string('cfg_authendpoint_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_authendpoint_desc', 'auth_cnoauth');
$configdefault = 'https://open.weixin.qq.com/connect/oauth2/authorize';
$settings->add(new admin_setting_configtext('auth_cnoauth/authendpoint', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_tokenendpoint_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_tokenendpoint_desc', 'auth_cnoauth');
$configdefault = 'https://api.weixin.qq.com/sns/oauth2/access_token';
$settings->add(new admin_setting_configtext('auth_cnoauth/tokenendpoint', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_userinfoendpoint_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_userinfoendpoint_desc', 'auth_cnoauth');
$configdefault = 'https://api.weixin.qq.com/sns/userinfo';
$settings->add(new admin_setting_configtext('auth_cnoauth/userinfoendpoint', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_cnoauthscope_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_cnoauthscope_desc', 'auth_cnoauth');
$configdefault = 'snsapi_userinfo';
$settings->add(new admin_setting_configtext('auth_cnoauth/cnoauthscope', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_redirecturi_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_redirecturi_desc', 'auth_cnoauth');
$settings->add(new auth_cnoauth_admin_setting_redirecturi('auth_cnoauth/redirecturi', $configkey, $configdesc));

$configkey = new lang_string('cfg_forceredirect_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_forceredirect_desc', 'auth_cnoauth');
$configdefault = 0;
$settings->add(new admin_setting_configcheckbox('auth_cnoauth/forceredirect', $configkey, $configdesc, $configdefault));

$label = new lang_string('cfg_debugmode_key', 'auth_cnoauth');
$desc = new lang_string('cfg_debugmode_desc', 'auth_cnoauth');
$settings->add(new \admin_setting_configcheckbox('auth_cnoauth/debugmode', $label, $desc, '0'));

$configkey = new lang_string('cfg_icon_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_icon_desc', 'auth_cnoauth');
$configdefault = 'auth_cnoauth:wechat';
$icons = [
    [
        'pix' => 'wechat',
        'alt' => new lang_string('cfg_iconalt_wechat', 'auth_cnoauth'),
        'component' => 'auth_cnoauth',
    ],
    [
        'pix' => 't/locked',
        'alt' => new lang_string('cfg_iconalt_locked', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/lock',
        'alt' => new lang_string('cfg_iconalt_lock', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/go',
        'alt' => new lang_string('cfg_iconalt_go', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/stop',
        'alt' => new lang_string('cfg_iconalt_stop', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/user',
        'alt' => new lang_string('cfg_iconalt_user', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'u/user35',
        'alt' => new lang_string('cfg_iconalt_user2', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/permissions',
        'alt' => new lang_string('cfg_iconalt_key', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/cohort',
        'alt' => new lang_string('cfg_iconalt_group', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/groups',
        'alt' => new lang_string('cfg_iconalt_group2', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/mnethost',
        'alt' => new lang_string('cfg_iconalt_mnet', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/permissionlock',
        'alt' => new lang_string('cfg_iconalt_userlock', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/more',
        'alt' => new lang_string('cfg_iconalt_plus', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/approve',
        'alt' => new lang_string('cfg_iconalt_check', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/right',
        'alt' => new lang_string('cfg_iconalt_rightarrow', 'auth_cnoauth'),
        'component' => 'moodle',
    ],
];
$settings->add(new auth_cnoauth_admin_setting_iconselect('auth_cnoauth/icon', $configkey, $configdesc, $configdefault, $icons));

$configkey = new lang_string('cfg_customicon_key', 'auth_cnoauth');
$configdesc = new lang_string('cfg_customicon_desc', 'auth_cnoauth');
$setting = new admin_setting_configstoredfile('auth_cnoauth/customicon', $configkey, $configdesc, 'customicon');
$setting->set_updatedcallback('auth_cnoauth_initialize_customicon');
$settings->add($setting);

// Tools to clean up tokens.
$cleanupcnoauthtokensurl = new moodle_url('/auth/cnoauth/cleanupcnoauthtokens.php');
$cleanupcnoauthtokenslink = html_writer::link($cleanupcnoauthtokensurl, get_string('cfg_cleanupcnoauthtokens_key', 'auth_cnoauth'));
$settings->add(new auth_cnoauth_admin_setting_label('auth_cnoauth/cleaniodctokens', $cleanupcnoauthtokenslink,
    get_string('cfg_cleanupcnoauthtokens_desc', 'auth_cnoauth')));
