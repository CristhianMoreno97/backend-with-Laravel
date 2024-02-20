<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Http\Responses\ApiResponse;
use App\Models\RefreshToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Models\User;

class AuthController extends Controller
{
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:100',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return ApiResponse::send(null, $validator->errors(), 422);
        }

        $credentials = $validator->validated();

        if (!$token = auth()->attempt($credentials)) {
            return ApiResponse::send(null, 'Credentials are invalid', 401);
        }
        
        RefreshToken::where('user_id', auth()->id())->delete();
        // TODO: allow multiple refresh tokens per user for multiple devices  

        $refreshToken = Str::random(64);

        $refreshTokenObj = new RefreshToken;
        $refreshTokenObj->user_id = auth()->id();
        $refreshTokenObj->token = hash('sha256', $refreshToken);
        $refreshTokenObj->expires_at = now()->addDays(7);
        $refreshTokenObj->save();

        return $this->respondWithToken($token, $refreshToken);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return ApiResponse::send(auth()->user(), 'Success', 200);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return ApiResponse::send(null, 'Successfully logged out', 200);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(Request $request)
    {
        $refreshToken = $request->cookie('refreshToken');

        if (!$refreshToken) {
            return ApiResponse::send(null, 'No refresh token provided', 401);
        }

        $hashRefreshToken = hash('sha256', $refreshToken);
        $tokenRecord = RefreshToken::where('token', $hashRefreshToken)->first();

        if (!$tokenRecord) {
            return ApiResponse::send(null, 'Refresh token is invalid', 401);
        }
        
        if ($tokenRecord->expires_at < now()) {
            return ApiResponse::send(null, 'Refresh token is expired', 401);
        }

        $user = User::find($tokenRecord->user_id);

        if (!$user) {
            return ApiResponse::send(null, 'User not found', 404);
        }

        $newAccessToken = auth()->login($user);

        return $this->respondWithToken($newAccessToken);
    }
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token, $refreshToken = null)
    {
        $response = [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ];
    
        if ($refreshToken) {
            $cookie = cookie('refreshToken', $refreshToken, 60 * 24 * 7, "/", null, null, true, false, 'Lax');
            return ApiResponse::send($response, 'Success', 200, $cookie);
        }
    
        return ApiResponse::send($response, 'Success', 200);
    }


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'string',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'password_confirmation' => 'required'
        ]);

        if ($validator->fails()) {
            return ApiResponse::send(null, $validator->errors(), 422);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        return ApiResponse::send($user, 'User successfully registered', 201);
    }
}
