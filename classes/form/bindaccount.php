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
 * User sign-up form.
 *
 * @package    core
 * @subpackage auth
 * @copyright  1999 onwards Martin Dougiamas  http://dougiamas.com
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_cnoauth\form;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/formslib.php');
require_once($CFG->dirroot.'/user/profile/lib.php');
require_once($CFG->dirroot . '/user/editlib.php');
require_once('lib.php');

class bindaccount extends \moodleform  {  //implements renderable, templatable
    function definition() {
        global $USER, $CFG;

        $mform = $this->_form;

        $mform->addElement('header', 'binduser', '绑定已有账号', '');


        $mform->addElement('text', 'username', get_string('username'), 'maxlength="100" size="12" autocapitalize="none"');
        $mform->setType('username', PARAM_RAW);
        $mform->addRule('username', get_string('missingusername'), 'required', null, 'client');

        if (!empty($CFG->passwordpolicy)){
            $mform->addElement('static', 'passwordpolicyinfo', '', print_password_policy());
        }
        $mform->addElement('password', 'password', get_string('password'), 'maxlength="32" size="12"');
        $mform->setType('password', PARAM_RAW);
        $mform->addRule('password', get_string('missingpassword'), 'required', null, 'client');

        // 记录数据
        $mform->addElement('hidden', 'cnoauthuniqid', $this->_customdata['cnoauthuniqid']);
        $mform->setType('cnoauthuniqid', PARAM_RAW);

        // buttons
        $this->add_action_buttons(true, '绑定账号');

    }

    function definition_after_data(){
        $mform = $this->_form;
        $mform->applyFilter('username', 'trim');

        // Trim required name fields.
        foreach (useredit_get_required_name_fields() as $field) {
            $mform->applyFilter($field, 'trim');
        }
    }

    /**
     * Validate user supplied data on the signup form.
     *
     * @param array $data array of ("fieldname"=>value) of submitted data
     * @param array $files array of uploaded files "element_name"=>tmp_file_path
     * @return array of "element_name"=>"error_description" if there are errors,
     *         or an empty array if everything is OK (true allowed for backwards compatibility too).
     */
    public function validation($data, $files) {
        global $DB;
        $errors = parent::validation($data, $files);

        // 查看user表是否存在对应用户的记录
        $user = $DB->get_record('user', array('username'=>$data['username']));
        if($user){
            $user = authenticate_user_login($data['username'], $data['password'], true); 
            if (!$user){
                // 登录失败
                $errors['password'] = "请检查账号密码是否输入正确。"; 
                return $errors;
            } else{  
                // 登录成功

                // 查询是否其他用户已绑定账号
                $cnoauthuniqid = $this->_customdata['cnoauthuniqid'];
                $rt = $DB->count_records_sql("select count(1) from {auth_cnoauth_token} where cnoauthuniqid = ? and (userid != ? and userid != 0 )",[$cnoauthuniqid, $user->id]);
    
                if($rt>0){
                    $errors['username'] = "此微信已绑定其他账号，请解绑后进行操作。".$rt;
                }else{
                    // 绑定用户信息
                    // 更新user表记录字段值
                    $user->phone2 = $cnoauthuniqid;
                    // $DB->update_record('user', $user);  // phone2字段限制，需要找另外的字段

                    // 更新auth_cnoauth_token表记录字段值
                    $token = $DB->get_record('auth_cnoauth_token', array('cnoauthuniqid'=>$cnoauthuniqid));
                    if($token){
                        $token->userid = $user->id;
                        $DB->update_record('auth_cnoauth_token', $token);
                    }
                    
                }
                
            }
        } else{
            $errors['password'] = "请检查账号密码是否输入正确。"; 
        }

        return $errors;
    }

    // /**
    //  * Export this data so it can be used as the context for a mustache template.
    //  *
    //  * @param renderer_base $output Used to do a final render of any components that need to be rendered for export.
    //  * @return array
    //  */
    // public function export_for_template(renderer_base $output) {
    //     ob_start();
    //     $this->display();
    //     $formhtml = ob_get_contents();
    //     ob_end_clean();
    //     $context = [
    //         'formhtml' => $formhtml
    //     ];
    //     return $context;
    // }
}
