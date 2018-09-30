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
 * Authentication Plugin: External Webservice Authentication
 *
 * Checks against an external webservice.
 *
 * @package    auth_ws
 * @author     Daniel Neis Araujo
 * @license    http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

/**
 * External webservice authentication plugin.
 */
class auth_plugin_ws extends auth_plugin_base {

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'ws';
        $this->config = get_config('auth_ws');

        if (isset($this->config->default_params) && !empty($this->config->default_params)) {
            $params = explode(',', $this->config->default_params);
            $defaultparams = array();
            foreach ($params as $p) {
                list($paramname, $value) = explode(':', $p);
                $defaultparams[$paramname] = $value;
            }
            $this->config->ws_default_params = $defaultparams;
        } else {
            $this->config->ws_default_params = array();
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
    public function user_login($username, $password) {

        $functionname = $this->config->auth_function;
        $params  = array($this->config->auth_function_username_paramname => $username,
                         $this->config->auth_function_password_paramname => $password);

        $result = $this->call_ws($this->config->serverurl, $functionname, $params);

        return ($result[$this->config->auth_function_resultClass][$this->config->auth_function_resultField] == true);
    }

    /**
     * This plugin is intended only to authenticate users.
     * User synchronization must be done by external service,
     * using Moodle's webservices.
     *
     * @param progress_trace $trace
     * @param bool $doupdates  Optional: set to true to force an update of existing accounts
     * @return int 0 means success, 1 means failure
     */
    public function sync_users(progress_trace $trace, $doupdates = false) {
        global $DB;

        $functionname = 'GetAlunos';
        $params = array('sParametrosBusca' => 'Inadimplente=0');
        $dbman = $DB->get_manager();
        $table = new xmldb_table('tmp_extuser');
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', XMLDB_UNSIGNED, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('username', XMLDB_TYPE_CHAR, '100', null, XMLDB_NOTNULL, null, null);
        $table->add_field('firstname', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null);
        $table->add_field('email', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null);
        $table->add_key('primary', XMLDB_KEY_PRIMARY, array('id'));
        $table->add_index('username', XMLDB_INDEX_UNIQUE, array('username'));

        print_string('creatingtemptable', 'auth_ws', 'tmp_extuser');
        $dbman->create_temp_table($table);

        print_string('fetchingstudents', 'auth_ws');
        $result = $this->call_ws($this->config->serverurl, $functionname, $params);

        print_string('savingtotemptable', 'auth_ws');
        foreach ($result->GetAlunosResult->wsAluno as $user) {
            $newuser = array('username'=> $user->LoginPortal,
                             'firstname' => $user->Nome, 'email' => $user->Email);
            $DB->insert_record_raw('tmp_extuser', $newuser, false);
        }

        /// preserve our user database
        /// if the temp table is empty, it probably means that something went wrong, exit
        /// so as to avoid mass deletion of users; which is hard to undo
        $count = $DB->count_records_sql('SELECT COUNT(*) AS count, 1 FROM {tmp_extuser}');
        if ($count < 1) {
            print_string('didntgetusersfromws', 'auth_ws');
            exit;
        } else {
            print_string('gotcountrecordsfromws', 'auth_ws', $count);
        }

        $sql = 'SELECT e.*
                  FROM {tmp_extuser} e
             LEFT JOIN {user} u
                    ON (e.username = u.username)
                 WHERE u.id IS NULL';
        $add_users = $DB->get_records_sql($sql);
        if (!empty($add_users)) {
            foreach ($add_users as $user) {
                $user->confirmed = 1;
                $user->auth = $this->authtype;
                $id = user_create_user($user, false);
                echo 'creted user: '.$user->firstname.'<br/>';
            }
        }

        echo 'updating users...<br/>';
        $sql = 'UPDATE {user} u
                  JOIN {tmp_extuser} e
                    ON (e.username = u.username)
                   SET u.firstname = e.firstname,
                       u.email = e.email,
                       u.suspended = 0,
                       u.deleted = 0,
                       u.confirmed = 1
                 WHERE u.auth = "ws"';
        echo 'users updated.<br/>';

        $sql = 'SELECT u.id,u.username
                  FROM {user} u
             LEFT JOIN {tmp_extuser} e
                    ON (e.username = u.username)
                 WHERE e.id IS NULL
                   AND u.auth = "ws"
                   AND u.deleted = 0
                   AND u.suspended = 0';
        $remove_users = $DB->get_records_sql($sql);
        foreach ($remove_users as $user) {
            $updateuser = new stdClass();
            $updateuser->id = $user->id;
            $updateuser->suspended = 1;
            user_update_user($updateuser, false);
            echo print_string('suspenduser', 'auth_db', array('name'=>$user->username, 'id'=>$user->id));
            echo "<br/>";
            \core\session\manager::kill_user_sessions($user->id);
        }
        return true;
    }

    public function get_userinfo($username) {
        return array();
    }

    private function call_ws($serverurl, $functionname, $params = array()) {

        $serverurl = $serverurl . '?wsdl';

        $params = array_merge($this->config->ws_default_params, $params);

        $client = new SoapClient($serverurl);
        try {
            $resp = $client->__soapCall($functionname, array($params));

            return $resp;
        } catch (Exception $e) {
            echo "Exception:\n";
            echo $e->getMessage();
            echo "===\n";
            return false;
        }
    }

    public function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal() {
        return false;
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from auth_plugin_base::get_userinfo().
     * The external service is responsible to update user records.
     *
     * @return bool true means automatically copy data from ext to user table
     */
    public function is_synchronised_with_external() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    public function can_change_password() {
        return false;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    public function change_password_url() {
        if (isset($this->config->changepasswordurl) && !empty($this->config->changepasswordurl)) {
            return new moodle_url($this->config->changepasswordurl);
        } else {
            return null;
        }
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    public function can_reset_password() {
        return false;
    }
}
