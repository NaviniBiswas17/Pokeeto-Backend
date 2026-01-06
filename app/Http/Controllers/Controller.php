<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Models\UserDetail;
use App\Models\EmailOtp;
use App\Models\EmailTemplate;
use App\Models\MailLog;
use App\Mail\MailTemp;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Mail;
use App\Http\Controllers\Exception;
use App\Models\Expenses;

class Controller
{
    public function login(Request $request)
    {
        try {
            if (isset($request->email) && isset($request->password)) {
                $request->validate([
                    'email' => 'required|email',
                    'password' => 'required',
                ]);

                $user = User::where(['email' => $request->email, 'status' => 1])->first();

                if (!$user || !Hash::check($request->password, $user->password)) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $token = $user->createToken('api-token')->plainTextToken;

                User::where('id', $user->id)->update(['email_verified_at' => now(), 'remember_token' => $token]);
                return response()->json([
                    'status' => true,
                    'message' => 'Login successful',
                    'access_token' => $token,
                ]);
            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function register(Request $request)
    {
        try {
            if (isset($request->name) && isset($request->email) && isset($request->phone) && isset($request->dob)) {
                $request->validate([
                    'name' => 'required|string',
                    'email' => 'required|email',
                    'phone' => 'required|string',
                    'dob' => 'required|date',
                ]);

                User::create([
                    "name" => $request->name,
                    "email" => $request->email,
                    "password" =>   hash::make('12346'),
                ]);
                $user = User::where('email', $request->email)->first();
                UserDetail::create([
                    "user_id" => $user->id,
                    "name" => $request->name,
                    "email" => $request->email,
                    "phone" => $request->phone,
                    "dob" => $request->dob
                ]);
                $otp = '123456'; // Generate OTP here
                $mailTemp = EmailTemplate::where('slug', 'registerOTP')->first();
                $html = Blade::render($mailTemp->body, [
                    'otp' => $otp,
                    'validity_minutes' => env('OTP_VALIDITY_MINUTES', 10)
                ]);
                Mail::to($request->email)->send(new MailTemp($html, $mailTemp->subject));
                EmailOtp::where('email', $request->email)->where('purpose', 'register')->update(['status' => '0']);
                EmailOtp::create([
                    "email" => $request->email,
                    "otp" => $otp,
                    "purpose" => 'register',
                    "expires_at" => now()->addMinutes((int) env('OTP_VALIDITY_MINUTES', 10)),
                ]);
                MailLog::create([
                    'to_email' => $request->email,
                    'subject' => $mailTemp->subject,
                    'body' => $html,
                    'sent_at' => now(),
                ]);
                $token = $user->createToken('api-token')->plainTextToken;

                User::where('id', $user->id)->update(['email_verified_at' => now(), 'remember_token' => $token]);
                return response()->json([
                    'status' => true,
                    'message' => 'Otp Sent successfully',
                    'access_token' => $token,

                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function verifyOtp(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->otp)) {
                $request->validate([
                    'token' => 'required',
                    'otp' => 'required',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $otpRecord = EmailOtp::where('email', $user->email)
                    ->where('otp', $request->otp)
                    ->where('purpose', 'register')
                    ->where('expires_at', '>', now())
                    ->where('status', '=', '1')
                    ->latest()
                    ->first();
                if (!$otpRecord) {
                    return response()->json(['status' => false, 'message' => 'Invalid or expired OTP'], 400);
                }
                $otpRecord->update(['used_at' => now(), 'status' => '0']);
                $token = $user->createToken('api-token')->plainTextToken;

                User::where('id', $user->id)->update(['email_verified_at' => now(), 'remember_token' => $token]);
                return response()->json([
                    'status' => true,
                    'access_token' => $token,
                    'message' => 'Otp Verified successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function confirmPass(Request $request)
    {
        try {
            if (isset($request->token)) {
                $request->validate([
                    'token' => 'required',
                    "newPass" => 'required',
                    "confirmPass" => 'required',
                ]);

                $user = User::where('remember_token', $request->token)->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'User not found'], 404);
                }

                if($request->newPass !== $request->confirmPass){
                    return response()->json(['status' => false, 'message' => 'Password and Confirm Password do not match'], 400);
                }
                $token = $user->createToken('api-token')->plainTextToken;
                User::where('id', $user->id)->update(['email_verified_at' => now(), 'password' => Hash::make($request->newPass), 'remember_token' => $token]);
                return response()->json([
                    'status' => true,
                    'access_token' => $token,
                    'message' => 'Password created successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    // Add expenses Controller

    // public function createExpenses(Request $request)
    // {
    //     try {
    //         if (isset($request->token) && isset($request->id) && isset($request->amount) && isset($request->account_type) && isset($request->category) && isset($request->comments)) {

    //             $request->validate([
    //                 'amount' => ['required', 'numeric',],
    //                 'account_type' => ['required', 'string'],
    //                 'category' => ['required', 'string'],
    //                 'date' => ['required', 'date'],
    //                 'comments' => ['required', 'string'],

    //             ]);
    //             $modelClass = $request->attributes->get('modelClass');

    //             if (!$modelClass || !class_exists($modelClass)) {
    //                 return response()->json(['status' => false, 'message' => 'Model not found'], 404);
    //             }
    //             $expenses = (new $modelClass)->where(['remember_token' => $request->token, 'status' => 1])->first();
    //             if (!$expenses) {
    //                 return response()->json(['status' => false, 'message' => 'expenses not found'], 404);
    //             }


    //             $expenses = Expenses::create([
    //                 'id' => $request->id,
    //                 'amount' => $request->amount,
    //                 'account_type' => $request->accountType,
    //                 'category' => $request->category,
    //                 'date' => $request->date,
    //                 'comments' => $request->comments,
    //             ]);
    //             if ($expenses) {
    //                 return response()->json(['status' => true, 'message' => 'Expenses created successfully'], 201);
    //             } else {
    //                 return response()->json(['status' => false, 'message' => 'Expenses Creation Error'], 404);
    //             }
    //         } else {
    //             return response()->json(['status' => false, 'message' => 'Parameters Empty'], 400);
    //         }
    //     } catch (\Exception $e) {
    //         return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
    //     }
    // }


}
