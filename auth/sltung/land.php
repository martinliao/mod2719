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
 * Authentication Plugin: Moodle Network Authentication
 * Multiple host authentication support for Moodle Network.
 *
 * @package auth_mnet
 * @author Martin Dougiamas
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

require_once dirname(dirname(dirname(__FILE__))) . '/config.php';
require_once $CFG->dirroot . '/mnet/xmlrpc/client.php';
require_once("HttpClient.class.php");

// grab the GET params
//$wantsurl      = required_param('wantsurl', PARAM_LOCALURL);
$username = required_param('User', PARAM_RAW);
$authkey  = required_param('AuthKey', PARAM_RAW);
//debugBreak();
$wantsurl = '/';
$url = new moodle_url('/auth/sltung/land.php', array('User'=>$username, 'AuthKey'=>$authkey, 'wantsurl'=>$wantsurl));
$PAGE->set_url($url);

$site = get_site();
$config = get_config('auth/sltung');

if (!is_enabled_auth('sltung')) {
    print_error('sltungdisable');
}

// confirm the SLTUNG session
$client = new HttpClient('10.6.51.133');
$loginurl = '/EIP/service/KM/verifyAuth.php';
if($config->debugauthdb){
    $client->setDebug(true);
}
if (!$client->post($loginurl, array(
        'User' => $username,
        'AuthKey' => $authkey
    )))
{
    die('An error occurred: '.$client->getError());
    //debugging(get_string('auth_sltungcantconnect','auth_sltung'));
    //        return false;
}
$returnvalue = $client->getContent();
if(strtolower($returnvalue) == 'true'){
  //return true;
}
else{
    print_error('unknownerror', 'auth_sltung');
    exit;
}
}

// get the local record for the remote user
$localuser = $DB->get_record('user', array('username'=>$username));

// log in
$user = get_complete_user_data('id', $localuser->id, $localuser->mnethostid);
complete_user_login($user);
// now that we've logged in, set up the mnet session properly
//$sltungauth->update_mnet_session($user, $token, $remotepeer);

//if (!empty($localuser->mnet_foreign_host_array)) {
//    $USER->mnet_foreign_host_array = $localuser->mnet_foreign_host_array;
//}

// redirect
if ($wantsremoteurl) {
    redirect($remotewwwroot . $wantsurl);
}
redirect($CFG->wwwroot . $wantsurl);


