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
 * Authentication Plugin: External Database Authentication
 *
 * Checks against an external database.
 *
 * @package    auth_sltung
 * @author     Jack Liou <jack@click-ap.com>
 * @copyright  2017 Click-AP {@link https://www.click-ap.com}
 * @license    http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once("HttpClient.class.php");
/**
 * External database authentication plugin.
 */
class auth_plugin_sltung extends auth_plugin_base {
    
    var $users = array();

    /**
     * Constructor.
     */
    function __construct() {
        global $CFG;
        $this->authtype = 'sltung';
        $this->config = get_config('auth/sltung');
        if (empty($this->config->extencoding)) {
            $this->config->extencoding = 'utf-8';
        }
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $CFG, $DB;

        $extusername = core_text::convert($username, 'utf-8', $this->config->extencoding);
        $extpassword = core_text::convert($password, 'utf-8', $this->config->extencoding);
        $extpassword = md5($extpassword);

        $host = $this->config->authhost;
        $url  = $this->config->authurl;
        
        //$client = new HttpClient('http://eip.sltung.com.tw/EIP/service/SSO/chkUserPwd.php');
        //$client = new HttpClient('eip.sltung.com.tw');
        $client = new HttpClient($host);
        //$loginurl = '/EIP/service/SSO/chkUserPwd.php';
        $loginurl = $url;
        if($this->config->debugauthdb){
            $client->setDebug(true);
        }
        if (!$client->post($loginurl, array(
                'id' => $extusername,
                'pwd' => $extpassword
            )))
        {
            die('An error occurred: '.$client->getError());
            //debugging(get_string('auth_sltungcantconnect','auth_sltung'));
            //        return false;
        }
        $returnvalue = $client->getContent();
        //var_dump($returnvalue);
        if(strtolower($returnvalue) == 'true'){
          return true;
        }
        else{
          return false;
        }        
    }

    /**
     * Returns user attribute mappings between moodle and ldap.
     *
     * @return array
     */
    function sltung_attributes() {
        $moodleattributes = array();
        foreach ($this->userfields as $field) {
            if (!empty($this->config->{"field_map_$field"})) {
                $moodleattributes[$field] = $this->config->{"field_map_$field"};
            }
        }
        $moodleattributes['username'] = $this->config->fielduser;
        return $moodleattributes;
    }

    /**
     * Reads any other information for a user from external database,
     * then returns it in an array.
     *
     * @param string $username
     * @return array
     */
    function get_userinfo($username) {
        global $CFG;

        $extusername = core_text::convert($username, 'utf-8', $this->config->extencoding);
        $item = null;
        foreach($this->users as $user) {
            if ($user->emp_no == $extusername) {
                $item = $user;
                break;
            }
        }

        //$authdb = $this->sltung_init();

        // Array to map local fieldnames we want, to external fieldnames.
        $selectfields = $this->sltung_attributes();

        $result = array();
        // If at least one field is mapped from external sltung, get that mapped data.
        if ($selectfields && !empty($item)) {
            $fields_obj = (object)array_change_key_case((array)$item , CASE_LOWER);
            $select = array();
            foreach ($selectfields as $localname=>$externalname) {
                $result[$localname] = trim($fields_obj->{$externalname});
                //$result[$localname] = core_text::convert($fields_obj->{$externalname}, $this->config->extencoding, 'utf-8');
            }
        }
        return $result;
    }

    /**
     * Change a user's password.
     *
     * @param  stdClass  $user      User table object
     * @param  string  $newpassword Plaintext password
     * @return bool                 True on success
     */
    function user_update_password($user, $newpassword) {
        return false;
    }

    /**
     * Synchronizes user from external sltung to moodle user table.
     *
     * Sync should be done by using idnumber attribute, not username.
     * You need to pass firstsync parameter to function to fill in
     * idnumbers if they don't exists in moodle user table.
     *
     * Syncing users removes (disables) users that don't exists anymore in external sltung.
     * Creates new users and updates coursecreator status of users.
     *
     * This implementation is simpler but less scalable than the one found in the LDAP module.
     *
     * @param progress_trace $trace
     * @param bool $do_updates  Optional: set to true to force an update of existing accounts
     * @return int 0 means success, 1 means failure
     */
    function sync_users(progress_trace $trace, $do_updates=false) {
        global $CFG, $DB;

        // List external users.
        $userlist = $this->get_userlist();

        // Delete obsolete internal users.
        if (!empty($this->config->removeuser)) {

            $suspendselect = "";
            if ($this->config->removeuser == AUTH_REMOVEUSER_SUSPEND) {
                $suspendselect = "AND u.suspended = 0";
            }

            // Find obsolete users.
            if (count($userlist)) {
                list($notin_sql, $params) = $DB->get_in_or_equal($userlist, SQL_PARAMS_NAMED, 'u', false);
                $params['authtype'] = $this->authtype;
                $sql = "SELECT u.*
                          FROM {user} u
                         WHERE u.auth=:authtype AND u.deleted=0 AND u.mnethostid=:mnethostid $suspendselect AND u.username $notin_sql";
            } else {
                $sql = "SELECT u.*
                          FROM {user} u
                         WHERE u.auth=:authtype AND u.deleted=0 AND u.mnethostid=:mnethostid $suspendselect";
                $params = array();
                $params['authtype'] = $this->authtype;
            }
            $params['mnethostid'] = $CFG->mnet_localhost_id;
            $remove_users = $DB->get_records_sql($sql, $params);

            if (!empty($remove_users)) {
                require_once($CFG->dirroot.'/user/lib.php');
                $trace->output(get_string('auth_sltunguserstoremove','auth_sltung', count($remove_users)));

                foreach ($remove_users as $user) {
                    if ($this->config->removeuser == AUTH_REMOVEUSER_FULLDELETE) {
                        delete_user($user);
                        $trace->output(get_string('auth_sltungdeleteuser', 'auth_sltung', array('name'=>$user->username, 'id'=>$user->id)), 1);
                    } else if ($this->config->removeuser == AUTH_REMOVEUSER_SUSPEND) {
                        $updateuser = new stdClass();
                        $updateuser->id   = $user->id;
                        $updateuser->suspended = 1;
                        $updateuser = $this->clean_data($updateuser);
                        user_update_user($updateuser, false);
                        $trace->output(get_string('auth_sltungsuspenduser', 'auth_sltung', array('name'=>$user->username, 'id'=>$user->id)), 1);
                    }
                }
            }
            unset($remove_users);
        }

        if (!count($userlist)) {
            // Exit right here, nothing else to do.
            $trace->finished();
            return 0;
        }

        // Update existing accounts.
        if ($do_updates) {
            // Narrow down what fields we need to update.
            $all_keys = array_keys(get_object_vars($this->config));
            $updatekeys = array();
            foreach ($all_keys as $key) {
                if (preg_match('/^field_updatelocal_(.+)$/',$key, $match)) {
                    if ($this->config->{$key} === 'onlogin') {
                        array_push($updatekeys, $match[1]); // The actual key name.
                    }
                }
            }
            unset($all_keys); unset($key);

            // Only go ahead if we actually have fields to update locally.
            if (!empty($updatekeys)) {
                list($in_sql, $params) = $DB->get_in_or_equal($userlist, SQL_PARAMS_NAMED, 'u', true);
                $params['authtype'] = $this->authtype;
                $sql = "SELECT u.id, u.username
                          FROM {user} u
                         WHERE u.auth=:authtype AND u.deleted=0 AND u.username {$in_sql}";
                if ($update_users = $DB->get_records_sql($sql, $params)) {
                    $trace->output("User entries to update: ".count($update_users));

                    foreach ($update_users as $user) {
                        if ($this->update_user_record($user->username, $updatekeys)) {
                            $trace->output(get_string('auth_sltungupdatinguser', 'auth_sltung', array('name'=>$user->username, 'id'=>$user->id)), 1);
                        } else {
                            $trace->output(get_string('auth_sltungupdatinguser', 'auth_sltung', array('name'=>$user->username, 'id'=>$user->id))." - ".get_string('skipped'), 1);
                        }
                    }
                    unset($update_users);
                }
            }
        }


        // Create missing accounts.
        // NOTE: this is very memory intensive and generally inefficient.
        $suspendselect = "";
        if ($this->config->removeuser == AUTH_REMOVEUSER_SUSPEND) {
            $suspendselect = "AND u.suspended = 0";
        }
        $sql = "SELECT u.id, u.username
                  FROM {user} u
                 WHERE u.auth=:authtype AND u.deleted='0' AND mnethostid=:mnethostid $suspendselect";

        $users = $DB->get_records_sql($sql, array('authtype'=>$this->authtype, 'mnethostid'=>$CFG->mnet_localhost_id));

        // Simplify down to usernames.
        $usernames = array();
        if (!empty($users)) {
            foreach ($users as $user) {
                array_push($usernames, $user->username);
            }
            unset($users);
        }

        $add_users = array_diff($userlist, $usernames);
        unset($usernames);

        if (!empty($add_users)) {
            $trace->output(get_string('auth_sltunguserstoadd','auth_sltung',count($add_users)));
            // Do not use transactions around this foreach, we want to skip problematic users, not revert everything.
            foreach($add_users as $user) {
                $username = $user;
                if ($this->config->removeuser == AUTH_REMOVEUSER_SUSPEND) {

                    if ($old_user = $DB->get_record('user', array('username'=>$username, 'deleted'=>0, 'suspended'=>1, 'mnethostid'=>$CFG->mnet_localhost_id, 'auth'=>$this->authtype))) {
                        $DB->set_field('user', 'suspended', 0, array('id'=>$old_user->id));
                        $trace->output(get_string('auth_sltungreviveduser', 'auth_sltung', array('name'=>$username, 'id'=>$old_user->id)), 1);

                        // Trigger user_updated event.
                        \core\event\user_updated::create_from_userid($old_user->id)->trigger();

                        continue;
                    }
                }

                // Do not try to undelete users here, instead select suspending if you ever expect users will reappear.

                // Prep a few params.
                $user = $this->get_userinfo_asobj($user);
                $user->username   = $username;
                $user->confirmed  = 1;
                $user->auth       = $this->authtype;
                $user->mnethostid = $CFG->mnet_localhost_id;
                if (empty($user->lang)) {
                    $user->lang = $CFG->lang;
                }
                if (empty($user->calendartype)) {
                    $user->calendartype = $CFG->calendartype;
                }
                $user->timecreated = time();
                $user->timemodified = $user->timecreated;
                if ($collision = $DB->get_record_select('user', "username = :username AND mnethostid = :mnethostid AND auth <> :auth", array('username'=>$user->username, 'mnethostid'=>$CFG->mnet_localhost_id, 'auth'=>$this->authtype), 'id,username,auth')) {
                    $trace->output(get_string('auth_sltunginsertuserduplicate', 'auth_sltung', array('username'=>$user->username, 'auth'=>$collision->auth)), 1);
                    continue;
                }
                $user = $this->clean_data($user);
                try {
                    $id = $DB->insert_record ('user', $user); // it is truly a new user

                    // Trigger user_created event.
                    \core\event\user_created::create_from_userid($id)->trigger();

                    $trace->output(get_string('auth_sltunginsertuser', 'auth_sltung', array('name'=>$user->username, 'id'=>$id)), 1);
                } catch (moodle_exception $e) {
                    $trace->output(get_string('auth_sltunginsertusererror', 'auth_sltung', $user->username), 1);
                    continue;
                }
                // If relevant, tag for password generation.
                if ($this->is_internal()) {
                    set_user_preference('auth_forcepasswordchange', 1, $id);
                    set_user_preference('create_password',          1, $id);
                }
                // Make sure user context is present.
                context_user::instance($id);
            }
            unset($add_users);
        }
        $trace->finished();
        return 0;
    }

    function user_exists($username) {

        // Init result value.
        $result = false;

        $extusername = core_text::convert($username, 'utf-8', $this->config->extencoding);

        //$authdb = $this->sltung_init();

        $rs = $authdb->Execute("SELECT *
                                  FROM {$this->config->table}
                                 WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."' ");

        if (!$rs) {
            print_error('auth_sltungcantconnect','auth_sltung');
        } else if (!$rs->EOF) {
            // User exists externally.
            $result = true;
        }

        $authdb->Close();
        return $result;
    }


    function get_userlist() {
        
        // Fetch userlist.
        //$url = "http://eip.sltung.com.tw/EIP/gows.php?wtag=pvt.eln.getempinfo";
        $url = $this->config->perzurl;
        $var = $this->config->var;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,true);
        curl_setopt($ch, CURLOPT_POST,true);
        //curl_setopt($ch, CURLOPT_ENCODING ,"");

        //$input = array("var" => "eyJkbyI6IjEifQ==");
        $input = array("var" => $var);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $input);

        $output = curl_exec($ch);
        curl_close($ch);

        // 將結果使用base64解碼
        $rawresult = base64_decode($output);
        // 可將結果轉為json解碼
        $objresult = json_decode($rawresult);

        if($objresult->val->isSuccess !='Y'){
            print_error('auth_sltungcantconnect','auth_sltung');
        }
        $users = $objresult->val->resultList;

        $this->users = $users; 
        
        // Init result value.
        $result = array();

        if (sizeof($users) <= 0) {
            print_error('auth_sltungcantconnect','auth_sltung');
        } else {
            foreach( $users as $rec){
                $rec = (object)array_change_key_case((array)$rec , CASE_LOWER);
                array_push($result, $rec->emp_no);
            }
        }

        return $result;
    }

    /**
     * Reads user information from DB and return it in an object.
     *
     * @param string $username username
     * @return array
     */
    function get_userinfo_asobj($username) {
        $user_array = truncate_userinfo($this->get_userinfo($username));
        $user = new stdClass();
        foreach($user_array as $key=>$value) {
            $user->{$key} = $value;
        }
        return $user;
    }

    /**
     * will update a local user record from an external source.
     * is a lighter version of the one in moodlelib -- won't do
     * expensive ops such as enrolment.
     *
     * If you don't pass $updatekeys, there is a performance hit and
     * values removed from DB won't be removed from moodle.
     *
     * @param string $username username
     * @param bool $updatekeys
     * @return stdClass
     */
    function update_user_record($username, $updatekeys=false) {
        global $CFG, $DB;

        //just in case check text case
        $username = trim(core_text::strtolower($username));

        // get the current user record
        $user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id));
        if (empty($user)) { // trouble
            error_log("Cannot update non-existent user: $username");
            print_error('auth_sltungusernotexist','auth_sltung',$username);
            die;
        }

        // Ensure userid is not overwritten.
        $userid = $user->id;
        $updated = false;

        if ($newinfo = $this->get_userinfo($username)) {
            $newinfo = truncate_userinfo($newinfo);

            if (empty($updatekeys)) { // All keys? This does not support removing values.
                $updatekeys = array_keys($newinfo);
            }

            foreach ($updatekeys as $key) {
                if (isset($newinfo[$key])) {
                    $value = $newinfo[$key];
                } else {
                    $value = '';
                }

                if (!empty($this->config->{'field_updatelocal_' . $key})) {
                    if (isset($user->{$key}) and $user->{$key} != $value) { // Only update if it's changed.
                        $DB->set_field('user', $key, $value, array('id'=>$userid));
                        $updated = true;
                    }
                }
            }
        }

        if ($updated) {
            $DB->set_field('user', 'timemodified', time(), array('id'=>$userid));

            // Trigger user_updated event.
            \core\event\user_updated::create_from_userid($userid)->trigger();
        }
        return $DB->get_record('user', array('id'=>$userid, 'deleted'=>0));
    }

    /**
     * Called when the user record is updated.
     * Modifies user in external database. It takes olduser (before changes) and newuser (after changes)
     * compares information saved modified information to external sltung.
     *
     * @param stdClass $olduser     Userobject before modifications
     * @param stdClass $newuser     Userobject new modified userobject
     * @return boolean result
     *
     */
    function user_update($olduser, $newuser) {
        return true;
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     *
     * @param stfdClass $form
     * @param array $err errors
     * @return void
     */
     function validate_form($form, &$err) {
    }

    function prevent_local_passwords() {
        return !$this->is_internal();
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from auth_plugin_base::get_userinfo().
     *
     * @return bool true means automatically copy data from ext to user table
     */
    function is_synchronised_with_external() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return ($this->is_internal() or !empty($this->config->changepasswordurl));
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        if ($this->is_internal() || empty($this->config->changepasswordurl)) {
            // Standard form.
            return null;
        } else {
            // Use admin defined custom url.
            return new moodle_url($this->config->changepasswordurl);
        }
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return $this->is_internal();
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param stdClass $config
     * @param array $err errors
     * @param array $user_fields
     * @return void
     */
    function config_form($config, $err, $user_fields) {
        include 'config.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param srdClass $config
     * @return bool always true or exception
     */
    function process_config($config) {
        // set to defaults if undefined
        // auth 
        if (!isset($config->authhost)) {
            // 'http://eip.sltung.com.tw/EIP/service/SSO/chkUserPwd.php';
            $config->authhost = 'eip.sltung.com.tw';
        }
        if (!isset($config->authurl)) {
            $config->authurl = '/EIP/service/SSO/chkUserPwd.php';
        }
        if (!isset($config->fielduser)) {
            $config->fielduser = 'emp_no';
        }
        
        // SSO
        if (!isset($config->ssohost)) {
            // http://10.6.51.133/EIP/service/KM/verifyAuth.php
            $config->ssohost = 'eip.sltung.com.tw';
        }
        if (!isset($config->ssourl)) {
            $config->ssourl = '/EIP/service/KM/verifyAuth.php';
        }
        
        // personalize
        if (!isset($config->perzurl)) {
            $config->perzurl = 'http://eip.sltung.com.tw/EIP/gows.php?wtag=pvt.eln.getempinfo';
        }
        if (!isset($config->var)) {
            $config->var = 'eyJkbyI6IjEifQ==';
        }

        if (!isset($config->extencoding)) {
            $config->extencoding = 'utf-8';
        }

        if (!isset($config->debugauthdb)) {
            $config->debugauthdb = 0;
        }
        if (!isset($config->removeuser)) {
            $config->removeuser = AUTH_REMOVEUSER_KEEP;
        }
        if (!isset($config->changepasswordurl)) {
            $config->changepasswordurl = '';
        }

        // Save settings.
        // auth
        set_config('authhost',      $config->authhost,      'auth/sltung'); // eip.sltung.com.tw
        set_config('authurl',       $config->authurl,       'auth/sltung'); // /EIP/service/SSO/chkUserPwd.php  
        set_config('fielduser',     $config->fielduser,     'auth/sltung'); // emp_no
        
        // SSO
        set_config('ssohost',      $config->ssohost,        'auth/sltung'); // 10.6.51.133
        set_config('ssourl',       $config->ssourl,         'auth/sltung'); // /EIP/service/KM/verifyAuth.php
        
        // personalized
        set_config('perzurl',       $config->perzurl,       'auth/sltung'); // http://eip.sltung.com.tw/EIP/gows.php?wtag=pvt.eln.getempinfo
        set_config('var',           $config->var,           'auth/sltung'); // eyJkbyI6IjEifQ==
        
        set_config('extencoding',   trim($config->extencoding), 'auth/sltung');
        set_config('debugauthdb',   $config->debugauthdb,   'auth/sltung');        
        set_config('removeuser',    $config->removeuser,    'auth/sltung');
        set_config('changepasswordurl', trim($config->changepasswordurl), 'auth/sltung');

        return true;
    }

    /**
     * Add slashes, we can not use placeholders or system functions.
     *
     * @param string $text
     * @return string
     */
    function ext_addslashes($text) {
        if (empty($this->config->sybasequoting)) {
            $text = str_replace('\\', '\\\\', $text);
            $text = str_replace(array('\'', '"', "\0"), array('\\\'', '\\"', '\\0'), $text);
        } else {
            $text = str_replace("'", "''", $text);
        }
        return $text;
    }

    /**
     * Test if settings are ok, print info to output.
     * @private
     */
    public function test_settings() {
        global $CFG, $OUTPUT;

        // NOTE: this is not localised intentionally, admins are supposed to understand English at least a bit...

        raise_memory_limit(MEMORY_HUGE);

        if (empty($this->config->perzurl)) {
            echo $OUTPUT->notification('Personalize service URL not specified.', 'notifyproblem');
            return;
        }

        if (empty($this->config->fielduser)) {
            echo $OUTPUT->notification('Personalize username field not specified.', 'notifyproblem');
            return;
        }

        $olddebug = $CFG->debug;
        $olddisplay = ini_get('display_errors');
        ini_set('display_errors', '1');
        $CFG->debug = DEBUG_DEVELOPER;
        $olddebugauthdb = $this->config->debugauthdb;
        $this->config->debugauthdb = 1;
        error_reporting($CFG->debug);

        $url = $this->config->perzurl;
        $var = $this->config->var;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,true);
        curl_setopt($ch, CURLOPT_POST,true);
        //curl_setopt($ch, CURLOPT_ENCODING ,"");

        //$input = array("var" => "eyJkbyI6IjEifQ==");
        $input = array("var" => $var);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $input);

        $output = curl_exec($ch);
        if(curl_error($ch)){
            //echo 'error:' . curl_error($c);
            $this->config->debugauthdb = $olddebugauthdb;
            $CFG->debug = $olddebug;
            ini_set('display_errors', $olddisplay);
            error_reporting($CFG->debug);
            ob_end_flush();

            echo $OUTPUT->notification(curl_error($ch), 'notifyproblem');
            return;
        }
        curl_close($ch);

        // 將結果使用base64解碼
        $rawresult = base64_decode($output);
        // 可將結果轉為json解碼
        $objresult = json_decode($rawresult);

        echo $OUTPUT->notification($objresult->msg, 'notifysuccess');
        if(empty($objresult->val)){
            echo $OUTPUT->notification($objresult->err, 'notifyproblem');

        } else {
            if($objresult->val->isSuccess != 'Y'){
                echo $OUTPUT->notification($objresult->val->message, 'notifyproblem');
            } else {
                echo $OUTPUT->notification($objresult->val->message, 'notifysuccess');
                $users = $objresult->val->resultList;
                if (sizeof($users) <= 0) {
                    echo $OUTPUT->notification('Get data is empty.', 'notifyproblem');
                }else {
                    $columns = array_keys((array)$users[0]);
                    echo $OUTPUT->notification('Personalize contains following columns:<br />'.implode(', ', $columns), 'notifysuccess');        
                }
            }

        }

        $this->config->debugauthdb = $olddebugauthdb;
        $CFG->debug = $olddebug;
        ini_set('display_errors', $olddisplay);
        error_reporting($CFG->debug);
        ob_end_flush();
    }

    /**
     * Clean the user data that comes from an external database.
     *
     * @param array $user the user data to be validated against properties definition.
     * @return stdClass $user the cleaned user data.
     */
    public function clean_data($user) {
        if (empty($user)) {
            return $user;
        }

        foreach ($user as $field => $value) {
            // Get the property parameter type and do the cleaning.
            try {
                $property = core_user::get_property_definition($field);
                $user->$field = clean_param($value, $property['type']);
            } catch (coding_exception $e) {
                debugging("The property '$field' could not be cleaned.", DEBUG_DEVELOPER);
            }
        }

        return $user;
    }
}


