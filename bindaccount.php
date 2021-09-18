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

require_once(__DIR__.'/../../config.php');
require_once($CFG->dirroot . '/user/editlib.php');
require_once($CFG->libdir . '/authlib.php');
require_once('lib.php');
require_once(__DIR__.'/classes/form/bindaccount.php');

$cnoauthuniqid = optional_param('cnoauthuniqid', null, PARAM_TEXT); // 获得传入token的unionid
$redirecturl = optional_param('redirecturl', null, PARAM_TEXT); // 获得传入redirecturl，绑定后返回

$PAGE->set_url('/auth/cnoauth/bindaccount.php', array('cnoauthuniqid' => $cnoauthuniqid));
$PAGE->set_context(context_system::instance());    

$PAGE->navbar->ignore_active();    
$PAGE->set_pagelayout('login');
$PAGE->set_title('绑定用户');
$PAGE->set_heading($SITE->fullname);

echo $OUTPUT->header();
echo $OUTPUT->box_start();

// 绑定的输入表单
$mform = new \auth_cnoauth\form\bindaccount(null, array('cnoauthuniqid' => $cnoauthuniqid));    
if ($mform->is_cancelled()) {
    redirect(get_login_url());
} 

$data = $mform->get_data();
if (!$data) { // 没有获得数据，显示表单.
    $mform->display();
}else if (!empty($data->cnoauthuniqid)) {
    redirect(new \moodle_url($redirecturl)); // 返回到调用页面    
}
echo $OUTPUT->box_end();
echo $OUTPUT->footer();


