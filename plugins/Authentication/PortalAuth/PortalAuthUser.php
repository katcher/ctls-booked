<?php
/**
Copyright 2012-2017 Nick Korbel

This file is part of Booked Scheduler.

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

class PortalAuthUser
{
	private $netname;
	private $fname;
	private $lname;
	private $mail;
	private $phone;
	private $institution = 'Concordia University';

	/**
	 * @param $entry Net_LDAP2_Entry
	 * @param $mapping string[]|array
	 */
	public function __construct($netname, $firstname, $lastname, $mail, $phone)
	{
		$this->netname = $netname;
		$this->fname = $firstname;
		$this->lname = $lastname;
		$this->mail =  $mail;
		$this->phone = $phone;
	}

	public function GetNetname()
	{
		return $this->netname;
	}
	
	public function GetFirstName()
	{
		return $this->fname;
	}

	public function GetLastName()
	{
		return $this->lname;
	}

	public function GetEmail()
	{
		return $this->mail;
	}

	public function GetPhone()
	{
		return $this->phone;
	}

	public function GetInstitution()
	{
		return $this->institution;
	}

}

?>