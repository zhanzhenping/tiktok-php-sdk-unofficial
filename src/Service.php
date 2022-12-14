<?php
/**
 * Created by PhpStorm
 * USER Zhanzhenping
 * Date 2022/12/14   17:22
 */

namespace Tiktok;

use Tiktok\Handle\Userinfo;

class Service
{
	private $client;

	public $userinfo_v2;

	/**
	 * @return Client
	 */
	public function getClient()
	{
		return $this->client;
	}

	public function __construct(Client $client)
	{
		$this->client = $client;

		$this->userinfo_v2 = new Userinfo($this, Client::USER_INFO_URL_V2);
	}
}