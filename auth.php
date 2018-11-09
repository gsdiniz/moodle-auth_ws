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
                         $this->config->auth_function_password_paramname => $password,
                         'nTipoUsuario' => 0, 'sEmpresa' => 'marques');

        $result = $this->call_ws($this->config->serverurl, $functionname, $params);

        return ($result->{$this->config->auth_function_resultClass}->{$this->config->auth_function_resultField} == true);
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
        global $DB, $CFG;

        $dbman = $DB->get_manager();

        $trace->output(get_string('creatingtemptable', 'auth_ws', 'tmp_extuser'));
        $table = new xmldb_table('tmp_extuser');
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', XMLDB_UNSIGNED, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('username', XMLDB_TYPE_CHAR, '100', null, XMLDB_NOTNULL, null, null);
        $table->add_field('firstname', XMLDB_TYPE_CHAR, '100', null, XMLDB_NOTNULL, null, null);
        $table->add_field('lastname', XMLDB_TYPE_CHAR, '100', null, XMLDB_NOTNULL, null, null);
        $table->add_field('email', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null);
        $table->add_field('idnumber', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null);
        $table->add_key('primary', XMLDB_KEY_PRIMARY, array('id'));
        $table->add_index('username', XMLDB_INDEX_UNIQUE, array('username'));
        $table->add_index('idnumber', XMLDB_INDEX_UNIQUE, array('idnumber'));
        $dbman->create_temp_table($table);

        $trace->output(get_string('fetchingstudents', 'auth_ws'));
        $functionname = 'GetAlunos';
        $params = array('sParametrosBusca' => 'Inadimplente=0;SituacaoAlunoID=-1');
        $result = $this->call_ws($this->config->serverurl, $functionname, $params);

        $trace->output(get_string('savingtotemptable', 'auth_ws'));
        foreach ($result->GetAlunosResult->wsAluno as $user) {
            if (isset($user->Email) && !empty($user->Email) && !empty($user->LoginPortal)) {

                $nameexploded = explode(' ', trim($user->Nome));
                $lastname = array_pop($nameexploded);
                $firstname = implode($nameexploded, ' ');
                $newuser = array('idnumber' => $user->AlunoID, 'username'=> $user->LoginPortal,
                                 'firstname' => $firstname, 'email' => $user->Email, 'lastname' => $lastname);

                if ($existinguser = $DB->get_record('tmp_extuser', array('idnumber' => $newuser['idnumber']))) {
                    $trace->output('IDNUMBER duplicado: '. $existinguser->firstname. ' '.$existinguser->lastname. ' ' .$existinguser->idnumber);
                } else if ($existinguser = $DB->get_record('tmp_extuser', array('email' => $newuser['email']))) {
                    $trace->output('email duplicado: '. $newuser->firstname. ' '.$newuser->lastname. ' ' .$existinguser->idnumber);
                    $trace->output('email já existente: '. $existinguser->firstname. ' '.$existinguser->lastname.
                                   ' ' .$existinguser->email . ' ' . $existinguser->idnumber);
                } else {
                    $DB->insert_record_raw('tmp_extuser', $newuser, false);
                }
            } else {
                $trace->output('Usuario sem email ou loginportal: '. $user->AlunoID . ' - ' . $user->Nome);
            }
        }

        /// preserve our user database
        /// if the temp table is empty, it probably means that something went wrong, exit
        /// so as to avoid mass deletion of users; which is hard to undo
        $count = $DB->count_records_sql('SELECT COUNT(*) AS count, 1 FROM {tmp_extuser}');
        if ($count < 1) {
            $trace->output(get_string('didntgetusersfromws', 'auth_ws'));
            exit;
        } else {
            $trace->output(get_string('gotcountrecordsfromws', 'auth_ws', $count));
        }

        $sql = 'SELECT e.*
                  FROM {tmp_extuser} e
             LEFT JOIN {user} u
                    ON (e.idnumber = u.idnumber)
                 WHERE u.id IS NULL';
        $add_users = $DB->get_records_sql($sql);
        if (!empty($add_users)) {
            foreach ($add_users as $user) {
                $user->confirmed = 1;
                $user->auth = $this->authtype;
                $user->username = core_user::clean_field($user->username, 'username');
                $user->mnethostid = $CFG->mnet_localhost_id;
                $id = user_create_user($user, false);
                $trace->output('creted user: '.$user->firstname. ' '. $user->lastname);
            }
        }

        $trace->output('updating users...');
        $sql = 'UPDATE {user} u
                  JOIN {tmp_extuser} e
                    ON (u.idnumber = e.idnumber)
                   SET u.username = e.username,
                       u.firstname = e.firstname,
                       u.lastname = e.lastname,
                       u.email = e.email,
                       u.suspended = 0,
                       u.deleted = 0,
                       u.confirmed = 1
                 WHERE u.auth = "ws"';
        $DB->execute($sql);
        $trace->output('users updated.');

        $sql = 'SELECT u.id,u.username
                  FROM {user} u
             LEFT JOIN {tmp_extuser} e
                    ON (e.idnumber = u.idnumber)
                 WHERE e.id IS NULL
                   AND u.auth = "ws"
                   AND u.deleted = 0
                   AND u.suspended = 0
                   AND u.id > 2';
        $remove_users = $DB->get_records_sql($sql);
        foreach ($remove_users as $user) {
            $updateuser = new stdClass();
            $updateuser->id = $user->id;
            $updateuser->suspended = 1;
            user_update_user($updateuser, false);
            $trace->output(get_string('suspenduser', 'auth_ws', $user));
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
