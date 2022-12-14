<?php
/**
 * Created by PhpStorm
 * USER Zhanzhenping
 * Date 2022/12/14   17:18
 */

namespace Tiktok\Handle;

use Exception;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Request;

class Userinfo
{

	private $client;

	private $uri;

	public function __construct($service, $uri)
	{
		$this->client = $service->getClient();
		$this->uri = $uri;
	}


	/**
	 * @return mixed
	 * @throws Exception
	 * @description Get tiktok V2 user information
	 * @date 2022/12/14
	 * @author zhanzhenping
	 */
	public function get()
	{
		$credentials = $this->client->getCredentials();

		if (!$credentials['access_token']) {
			throw new Exception("missing access_token");
		}

		$body = Query::build([
			'fields' => 'open_id,union_id,avatar_url,display_name',
		]);

		$request = new Request(
			'GET',
			$this->uri . "?" . $body,
			[
				'Cache-Control' => 'no-store',
				'Content-Type'  => 'application/x-www-form-urlencoded',
				"Authorization" => " Bearer " . $credentials['access_token'],
			]
		);

		$response = $this->client->getHttpClient()->send($request);
		$body = (string)$response->getBody();

		// Assume it's JSON; if it's not throw an exception
		if (null === $res = json_decode($body, true)) {
			throw new \Exception('Invalid JSON response');
		}

		return $res['data'];
	}

}