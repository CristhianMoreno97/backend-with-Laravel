<?php

namespace App\Http\Responses;

class ApiResponse
{
    public static function send($data = null, $message = 'Success', $status = 200)
    {
        return response()->json([
            'data' => $data,
            'message' => $message,
            'status' => $status
        ], $status);
    }
}
