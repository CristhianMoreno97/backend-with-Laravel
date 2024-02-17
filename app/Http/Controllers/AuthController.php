<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Models\RefreshToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Models\User;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'refresh']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
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
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        $refreshToken = request('refresh_token');

        if (!$refreshToken) {
            return response()->json(['error' => 'No refresh token provided'], 401);
        }

        $hashRefreshToken = hash('sha256', $refreshToken);
        $tokenRecord = RefreshToken::where('token', $hashRefreshToken)->first();

        if (!$tokenRecord) {
            return response()->json(['error' => 'Refresh token is invalid'], 401);
        }
        
        if ($tokenRecord->expires_at < now()) {
            return response()->json(['error' => 'Refresh token is expired'], 401);
        }

        $user = User::find($tokenRecord->user_id);

        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }

        $newAccessToken = auth()->login($user);

        $newRefreshToken = Str::random(64);
        $tokenRecord->token = hash('sha256', $newRefreshToken);
        $tokenRecord->save();

        return $this->respondWithToken($newAccessToken, $newRefreshToken);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token, $refreshToken)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'refresh_token' => $refreshToken,
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'password_confirmation' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }
}
