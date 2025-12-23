<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use App\Models\User;


use App\Http\Controllers\Exception;

class AuthController extends Controller
{


 public function register(Request $request)
{
    $request->validate([
        'name'     => 'required|string|max:255',
        'email'    => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:8|confirmed',
    ]);

    $user = User::create([
        'name'     => $request->name,
        'email'    => $request->email,
        'password' => $request->password, // auto-hashed via casts
    ]);

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
        'status'  => true,
        'message' => 'User registered successfully',
        'user'    => [
            'id'    => $user->id,
            'name'  => $user->name,
            'email' => $user->email,
        ],
        'token'   => $token,
    ], 201);
}


   public function login(Request $request)
    {
        try{
            if(isset($request->email) && isset($request->password)) {
                $request->validate([
                'email' => 'required|email',
                'password' => 'required',
                ]);

                $user = User::where(['email' => $request->email, 'status' => 1])->first();

                if (! $user || ! Hash::check($request->password, $user->password)) {
                    $User = User::where(['email' => $request->email, 'status' => 1])->first();
                    if (! $User || ! Hash::check($request->password, $User->password)) {
                        return response()->json(['status'=>false,'message' => 'Invalid credentials'], 401);
                    }else{
                        $token = $User->createToken('api-token')->plainTextToken;

                        User::where('id', $User->id)->update(['email_verified_at' => now(),'remember_token' => $token]);
                        return response()->json([
                            'status'=>true,
                            'message' => 'Login successful',
                            'isPasswordChange'=> (Hash::check(env('DEFAULT_PASS'), $User->password)) ? true : false,
                            'access_token' => $token,
                            'token_type' => 'Bearer',
                        ]);
                    }
                }
                $token = $user->createToken('api-token')->plainTextToken;

                User::where('id', $user->id)->update(['email_verified_at' => now(),'remember_token' => $token]);
                return response()->json([
                    'status'=>true,
                    'message' => 'Login successful',
                    'isPasswordChange'=> (Hash::check(env('DEFAULT_PASS'), $user->password)) ? true : false,
                    'access_token' => $token,
                    'token_type' => 'Bearer',
                ]);
            }else{
                return response()->json(['status'=>false,'message' => 'Email and Password are required'], 400);
            }
        }
        catch(\Exception $e){
            return response()->json(['status'=>false,'message' => $e->getMessage()], 500);
        }

    }

    public function logout(Request $request) 
    {
        try{
            if(isset($request->token)) {
                $modelClass = $request->attributes->get('modelClass');

                if (!$modelClass || !class_exists($modelClass)) {
                    return response()->json(['status' => false, 'message' => 'Model not found'], 404);
                }
                $user = (new $modelClass)->where(['remember_token'=>$request->token,'status'=>1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'User not found'], 404);
                }
                $user->update([
                    'email_verified_at' => null,
                    'remember_token' => null,
                ]);
                return response()->json(['status'=>true,'message' => 'Logged out successfully']);
            } else {
                return response()->json(['status'=>false,'message' => 'Token is required'], 400);
            }
        }
        catch(\Exception $e){
            return response()->json(['status'=>false,'message' => $e->getMessage()], 500);
        }

    }

}
