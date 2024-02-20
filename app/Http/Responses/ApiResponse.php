<?php

namespace App\Http\Responses;

class ApiResponse
{
    public static function send($data = null, $message = 'Success', $status = 200, $cookie = null)
    {
        $response = response()->json([
            'data' => $data,
            'message' => $message,
            'status' => $status
        ], $status);
    
        if ($cookie) {
            $response = $response->withCookie($cookie);
        }
    
        return $response;
    }
}
