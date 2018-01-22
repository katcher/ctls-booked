<?php
/**
 File in Authentication plugin package for ver 2.1.4 Booked Scheduler
 to implement Single Sign On Capability.  Based on code from the
 Booked Scheduler Authentication Ldap plugin as well as a SAML
 Authentication plugin for Moodle 1.9+.
 See http://moodle.org/mod/data/view.php?d=13&rid=2574
 This plugin uses the SimpleSAMLPHP version 1.8.2 libraries.
 http://simplesamlphp.org/

 Booked Scheduler is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Booked Scheduler is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Booked Scheduler.  If not, see <http://www.gnu.org/licenses/>.
 */

require_once(ROOT_DIR . 'lib/Application/Authentication/namespace.php');
require_once(ROOT_DIR . 'plugins/Authentication/PortalAuth/namespace.php');

// global $netname;


class PortalAuth extends Authentication implements IAuthentication
{
	/**
	 * @var IAuthentication
	 */
	private $authToDecorate;
	private $netname;
	private $myuser;
	private $authconfig;
	
	public function SetRegistration($registration)
	{
		$this->_registration = $registration;
	}
	
	private function GetRegistration()
	{
		if ($this->_registration == null)
		{
			$this->_registration = new Registration();
		}
	
		return $this->_registration;
	}
	
	public function __construct(IAuthentication $authentication)
	{	
		$this->authToDecorate = $authentication;
		// Log::Debug('Options %s', print_r($this->options,1));
	}

	public function Validate($username, $password)
	{
		$token = $_GET['token'];
		$dbname = $_GET['dbname'];
		$this->netname = $this->GetUserFromToken($token, $dbname, PortalAuthConfig::REVAUTHURL);
		if($this->netname)
		{			
			$tmp = $this->GetConuUserInfo($this->netname, PortalAuthConfig::ORACLEHOST, PortalAuthConfig::ORACLEPORT, PortalAuthConfig::ORACLESERVICE, PortalAuthConfig::ORACLEUNAME, PortalAuthConfig::ORACLEPWD);
			if($tmp) {
				return true;
			}
			return false;
		}
		return false;
	}

	public function Login($username, $loginContext)
	{
		if( strlen($this->myuser->GetLastName()) > 0 )
		{
			$this->Synchronize($this->netname);
		}
		return $this->authToDecorate->Login($this->netname, $loginContext);
	}

	public function Logout(UserSession $user)
	{
		$this->authToDecorate->Logout($user);
	}

	public function AreCredentialsKnown()
	{
		return true;
	}

	public function ShowUsernamePrompt()
	{
		return false;
	}

	public function ShowPasswordPrompt()
	{
		return false;
	}

	public function ShowPersistLoginPrompt()
	{
		return false;
	}

	public function ShowForgotPasswordPrompt()
	{
		return false;
	}
	private function GetUserFromToken ($token, $dbname, $url) 
	{
		if (!is_null($token) and !is_null($dbname)) 
		{
			$tmp = ''; $error = (string) null; $msg = ''; $errno = '';
			$ReverseAuthurl= $url;		
			$ReverseAuthurl .= 'token='. urlencode($token) . '&dbname=' . urlencode($dbname);
			$options = array();
			$options = array(
					CURLOPT_URL => $ReverseAuthurl,
					CURLOPT_SSL_VERIFYHOST => 0,
					CURLOPT_SSL_VERIFYPEER => false,
					CURLOPT_HEADER => 0,
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_CONNECTTIMEOUT => 5,
					CURLOPT_TIMEOUT        => 5,
			);
			$ch = curl_init();
			curl_setopt_array($ch, $options);
			$res = curl_exec($ch);
			Log::Debug('ResultStr info %s',$res);				
			$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			Log::Debug('http_code: %s',$http_code);
			if($http_code == '200')
			{
				if(!strlen($res))
				{
					return false;
				}
				Log::Debug('Retrieve Username from xml res');
				$xml = simplexml_load_string($res);
				if(!$xml) 
				{					
					return false;
				}
				$authval = $xml->portalauth->attributes()->{'authenticated'};
				Log::Debug('Authenticated Attribute from $res: %s',$authval);
				if($authval == "true")
				{
					return $xml->portalauth->attributes()->{'portalId'};
				}
				else 
				{
					return false;
				}
			}
			else 
			{
				return false;
			}	
		
		}
		
	}

	private function GetConuUserInfo ($netname, $host, $port, $service, $dbuser, $dbpass)
	{
		Log::Debug ('In Get User %s Info from AD',$netname);
		/* Prepare Oracle Queries */
		// New Campus Views
		$oraclecfg = new stdClass();
		$oraclecfg->host = $host;
		$oraclecfg->port = $port;
		$oraclecfg->service = $service;
		$oraclecfg->username = $dbuser;
		$oraclecfg->password = $dbpass;
		$oracledb = $this->oracle_connect($oraclecfg);
		if($oracledb){
			$sql = "SELECT NETNAME, FIRSTNAME, LASTNAME, PHONE, EMAIL_ADDRESS, EMPLOYEE_STATUS, ACTIVE_STUDENT FROM CAMS.CAMS_N03_LIBRARY_VW WHERE UPPER(NETNAME) = :netname";
			// Log::Debug ('SQL: %s',$sql);
			$oraclerecords = $this->query_oracle($oracledb, $sql, array('netname' => strtoupper($netname)));
			$row = oci_fetch_assoc($oraclerecords);
			if(strlen($row['NETNAME']))
			{
				$this->myuser = new PortalAuthUser ($row['NETNAME'], $row['FIRSTNAME'], $row['LASTNAME'], $row['EMAIL_ADDRESS'], $row['PHONE']);
				return true;
			}
			return false;			
		}
		return false;		
	}
	private function Synchronize()
	{
		$registration = $this->GetRegistration();
	
		$registration->Synchronize(
		 new AuthenticatedUser(
			$this->myuser->GetNetname(),
			$this->myuser->GetEmail(),
			$this->myuser->GetFirstName(),
			$this->myuser->GetLastName(),
		 	null, 
			Configuration::Instance()->GetKey(ConfigKeys::LANGUAGE),
			Configuration::Instance()->GetDefaultTimezone(),
			$this->myuser->GetPhone(), 
		 	$this->myuser->GetInstitution()
		  )
		);
	}
	
	
	private function oracle_connect ($oraclecfg) {
		$connectstring = "(DESCRIPTION = (ADDRESS_LIST = (ADDRESS = (PROTOCOL = TCP)(HOST = $oraclecfg->host)(PORT = $oraclecfg->port)))" .
		" (CONNECT_DATA = (SERVER = DEDICATED) (SERVICE_NAME = $oraclecfg->service)))";
		// 	Log::Debug('Conncetion String: %s', $connectstring);		
		return oci_connect($oraclecfg->username, $oraclecfg->password,$connectstring, $oraclecfg->charset);
	}
	
	private function query_oracle($db, $sql, $params) {
		$statement = oci_parse($db, $sql);
		if ($statement === false) {
			print "Failed to parse statement:\n$sql\n";
			exit(1);
		}
		if(isset($params['netname']))
		{
			
			oci_bind_by_name($statement, ":netname", $params['netname']);
			Log::Debug('After Bind params: %s', $params['netname']);
		}
		$executeresult = oci_execute($statement, OCI_DEFAULT);
		if ($executeresult === false) {
			print "Failed to execute statement:\n$sql\n";
			exit(1);
		}
		return $statement;
	}
	
	
}

?>