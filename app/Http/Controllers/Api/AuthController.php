<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use GuzzleHttp\Client;
use Laravel\Passport\Client as OClient;

class AuthController extends Controller{

	public function refreshToken(Request $request){
		$request->validate([
			'refresh_token' => 'required'
		]);
		$oClient = OClient::where('password_client', 1)->first();
		return $this->getRefreshedToken($oClient, request('refresh_token'));
	}   

	public function login(Request $request){

		$request->validate([
			'email' => 'required|string',
			'password' => 'required|string'
		]);

		$credentials = request(['email', 'password']);

		if (!Auth::attempt($credentials)) {
			return response()->json([
				'message'=>'Invalid credentials'
			], 401);
		}

		$user = $request->user();
		$token = $user->createToken('Access_Token');
		$user->access_token = $token->accessToken;

		return response()->json([
			'user'=>$user
		], 200);
	}

	public function register(Request $request){
		
		$request->validate([
			'name' => 'required|string',
			'email' => 'required|string|email|unique:users',
			'password' => 'required|string|confirmed'
		]);

		$user = new User([
			'name'=>$request->name,
			'email'=>$request->email,
			'password'=>bcrypt($request->password)
		]);

		$user->save();
		$token = $user->createToken('Access_Token');
		$user->access_token = $token->accessToken;

		return response()->json([
			"message"=>"Success",
			'user'=>$user
		], 201);
	}

	public function logout(Request $request){
		$request->user()->token()->revoke();
		return response()->json([
			"message"=>"User logged out successfully"
		], 200);
	}

	public function index(Request $request){
		return response()->json([
			"user" => $request->user()
		], 200);
	}

	private function getTokens(OClient $oClient, $email, $password){
		$oClient = OClient::where('password_client', 1)->first();
		$http = new Client;

		$response = $http->request('POST', url('/').'/oauth/token', [
			'form_params' => [
				'grant_type' => 'password',
				'client_id' => $oClient->id,
				'client_secret' => $oClient->secret,
				'username' => $email,
				'password' => $password,
				'scope' => '*',
			],
		]);

		$result = json_decode((string) $response->getBody(), true);
		return response()->json($result, 200);
	}

	private function getRefreshedToken(OClient $oClient, $refresh_token){
		$oClient = OClient::where('password_client', 1)->first();
		$http = new Client;

		$response = $http->request('POST', url('/').'/oauth/token', [
			'form_params' => [
				'grant_type' => 'refresh_token',
				'refresh_token' => $refresh_token,
				'client_id' => $oClient->id,
				'client_secret' => $oClient->secret,
				'scope' => '*',
			],
		]);

		$result = json_decode((string) $response->getBody(), true);
		return response()->json($result, 200);

	}

}
