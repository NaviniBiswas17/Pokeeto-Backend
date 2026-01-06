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
use App\Models\Account;
use App\Models\AccountContributor;
use App\Models\Category;
use App\Models\UserCategory;
use App\Models\UserSetting;
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
                User::where('id', $user->id)->update(['email_verified_at' => now(), 'password' => Hash::make($request->newPass)]);
                return response()->json([
                    'status' => true,
                    'message' => 'Password created successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function addAccount(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->account_name) && isset($request->default_currency) && isset($request->balance) && isset($request->is_primary)) {
                $request->validate([
                    'token' => 'required',
                    'account_name' => 'required|string',
                    'default_currency' => 'required|string',
                    'balance' => 'required|numeric',
                    'is_primary' => 'required|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                Account::create([
                    "user_id" => $user->id,
                    "account_name" => $request->account_name,
                    "default_currency" => $request->default_currency,
                    "balance" => $request->balance,
                    "is_primary" => $request->is_primary,
                    'last_login_at' => now(),
                    "status" => 1
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Account added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getAccountList(Request $request)
    {
        try {
            if (isset($request->token)) {
                $request->validate([
                    'token' => 'required',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $accounts = Account::where(['user_id' => $user->id, 'status' => 1])->get();
                return response()->json([
                    'status' => true,
                    'message' => 'Account list fetched successfully',
                    'data' => $accounts
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function addContributor(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->account_id) && isset($request->contributor_id) && isset($request->role)) {
                $request->validate([
                    'token' => 'required',
                    'account_id' => 'required|integer',
                    'contributor_id' => 'required|integer',
                    'role' => 'required|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $contributorUser = User::where(['id' => $request->contributor_id, 'status' => 1])->first();
                if (!$contributorUser) {
                    return response()->json(['status' => false, 'message' => 'Contributor User not found'], 404);
                }
                AccountContributor::create([
                    "account_id" => $request->account_id,
                    "contributor_id" => $request->contributor_id,
                    "user_id" => $user->id,
                    "role" => $request->role,
                    "status" => 1
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Contributor added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function getContributorList(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->account_id)) {
                $request->validate([
                    'token' => 'required',
                    'account_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $contributors = AccountContributor::where(['account_id' => $request->account_id, 'status' => 1])->get();
                return response()->json([
                    'status' => true,
                    'message' => 'Contributor list fetched successfully',
                    'data' => $contributors
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function getUserCategoryList(Request $request)
    {
        try {
            if (isset($request->token)) {
                $request->validate([
                    'token' => 'required',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $categories = Category::where('status', operator: '1')->get();
                $userCategories = UserCategory::where(['user_id' => $user->id, 'status' => 1])->get();
                return response()->json([
                    'status' => true,
                    'message' => 'User Specific category list fetched successfully',
                    'data' => [
                        'categories' => $categories,
                        'user_categories' => $userCategories
                    ]
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function addUserCategory(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->name)  && isset($request->description)) {
                $request->validate([
                    'token' => 'required',
                    'name' => 'required|string',
                    'description' => 'required|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                UserCategory::create([
                    "user_id" => $user->id,
                    "name" => $request->name,
                    "description" => $request->description,
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'User Category added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function updateUserSetting(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->currency)  && isset($request->country) && isset($request->metadata)) {
                $request->validate([
                    'token' => 'required',
                    'currency' => 'required|string',
                    'country' => 'required|string',
                    'metadata' => 'required|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                UserSetting::updateOrCreate(
                    ['user_id' => $user->id],
                    [
                        "currency" => $request->currency,
                        "country" => $request->country,
                        "metadata" => $request->metadata,
                    ]
                );
                return response()->json([
                    'status' => true,
                    'message' => 'User Setting updated successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
}
