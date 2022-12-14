<?php
/**
 * Created by PhpStorm
 * USER Zhanzhenping
 * Date 2022/12/14   16:45
 */

namespace Tiktok\Token;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7;
use Tiktok\Client;

class RevokeToken
{
	private $http;

	public function __construct(ClientInterface $http = null)
	{
		$this->http = $http;
	}

	/**
	 * @throws Exception
	 * @throws GuzzleException
	 */
	public function revokeAccess($token)
	{
		if (!isset($token['open_id']) || !isset($token['access_token'])) {
			throw new Exception("Missing open_id or access_token parameter");
		}

		$body = Psr7\Utils::streamFor(http_build_query([
			'open_id' => $token['open_id'],
			'access_token' => $token['access_token']
		]));
		$request = new Request(
			'POST',
			Client::REVOKE_URL,
			[
				'Cache-Control' => 'no-store',
				'Content-Type'  => 'application/x-www-form-urlencoded',
			],
			$body
		);

		$response = $this->http->send($request);

		return $response->getStatusCode() == 200;
	}

}