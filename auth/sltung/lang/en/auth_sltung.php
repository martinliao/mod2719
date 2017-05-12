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
 * Strings for component 'auth_sltung', language 'en'.
 *
 * @package   auth_sltung
 * @auth       Jack Liou <jack@click-ap.com>
 * @copyright  2017 Click-AP {@link http://www.click-ap.com}
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$string['auth_sltungdescription'] = 'This authentication method should be used for sltung accounts that are exclusively for use by web-service clients.';
$string['pluginname'] = 'SLTUNG Web-services auth.';

$string['auth_dbextrafields'] = 'These fields are optional.  You can choose to pre-fill some Moodle user fields with information from the <b>external database fields</b> that you specify here. <p>If you leave these blank, then defaults will be used.</p><p>In either case, the user will be able to edit all of these fields after they log in.</p>';
$string['auth_authhost'] = 'Authentication Host';
$string['auth_authhost_key'] = 'Authentication Host';
$string['auth_authurl'] = 'Authentication URL';
$string['auth_authurl_key'] = 'Authentication URL';
$string['auth_fielduser'] = 'Name of the field containing usernames';
$string['auth_fielduser_key'] = 'Username field';
$string['auth_ssohost'] = 'SSO Host';
$string['auth_ssohost_key'] = 'SSO Host';
$string['auth_ssourl'] = 'SSO URL';
$string['auth_ssourl_key'] = 'SSO URL';
$string['auth_perzurl'] = 'Personalize service URL';
$string['auth_perzurl_key'] = 'Personalize URL';
$string['auth_var'] = 'Password matching the above personalize url';
$string['auth_var_key'] = 'Password';
$string['auth_dbextencoding'] = 'External db encoding';
$string['auth_dbextencodinghelp'] = 'Encoding used in external database';
$string['auth_dbdebugauthdb'] = 'Debug';
$string['auth_dbdebugauthdbhelp'] = 'Debug connection to external database - use when getting empty page during login. Not suitable for production sites.';
$string['auth_dbchangepasswordurl_key'] = 'Password-change URL';


$string['auth_sltunguserstoadd'] = 'User entries to add: {$a}';
$string['auth_sltungusernotexist'] = 'Cannot update non-existent user: {$a}';
$string['auth_sltunguserstoremove'] = 'User entries to remove: {$a}';
$string['auth_sltunginsertuser'] = 'Inserted user {$a->name} id {$a->id}';
$string['auth_sltunginsertuserduplicate'] = 'Error inserting user {$a->username} - user with this username was already created through \'{$a->auth}\' plugin.';