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
use App\Models\Transaction;
use App\Models\ReminderPayment;
use App\Mail\MailTemp;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Mail;
use App\Http\Controllers\Exception;
use App\Models\Expenses;
use App\Models\KidDetail;
use App\Models\KidGoal;
use App\Models\KidTask;
use App\Models\KidTransaction;
use App\Models\KidAccount;
use App\Models\FriendInvite;
use Illuminate\Support\Str;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;


class Controller
{
    // public function login(Request $request)
    // {
    //     try {
    //         if (isset($request->email) && isset($request->password)) {
    //             $request->validate([
    //                 'email' => 'required|email',
    //                 'password' => 'required',
    //             ]);

    //             $user = User::where(['email' => $request->email, 'status' => 1])->first();

    //             if (!$user || !Hash::check($request->password, $user->password)) {
    //                 return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
    //             }
    //             $token = $user->createToken('api-token')->plainTextToken;

    //             User::where('id', $user->id)->update(['email_verified_at' => now(), 'remember_token' => $token]);
    //             return response()->json([
    //                 'status' => true,
    //                 'message' => 'Login successful',
    //                 'access_token' => $token,
    //             ]);
    //         } else {
    //             return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
    //         }
    //     } catch (\Exception $e) {
    //         return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
    //     }
    // }

    public function loginGuest(Request $request)
    {
         try {
            if (isset($request->guestParam)) {
                $request->validate([
                    'guestParam' => 'required|regex:/^[A-Za-z]{4}[0-9]{5}$/',
                ]);
                $email = 'Pockeeto'.rand(00,99).time().'@pockeetoGuest.com';
                while(User::where('email', $email)->exists()){
                    $email = 'Pockeeto'.rand(00,99).time().'@pockeetoGuest.com';
                }
                $request->merge(['email' => $email]);
                $name = explode('@', $request->email)[0];
                $request->merge(['name' => $name]);

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
                ]);

                Account::create([
                    "user_id" => $user->id,
                    "account_name" => 'Main Account',
                    "default_currency" => 'INR',
                    "balance" => 0,
                    "is_primary" => '1',
                    'last_login_at' => now()
                ]);
                $token = $user->createToken('api-token')->plainTextToken;

                User::where('id', $user->id)->update(['email_verified_at' => now(), 'remember_token' => $token]);
                return response()->json([
                    'status' => true,
                    'message' => 'Login Successful',
                    'access_token' => $token,

                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function sendOtp(Request $request)
    {
        try {
            if (isset($request->email)) {
                $request->validate([
                    'email' => 'required|email',
                ]);
                $user = User::where(['email' => $request->email, 'status' => 1])->first();
                if (!$user) {
                    $name = explode('@', $request->email)[0];
                    $request->merge(['name' => $name]);

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
                    ]);
                    Account::create([
                        "user_id" => $user->id,
                        "account_name" => 'Main Account',
                        "default_currency" => 'INR',
                        "balance" => 0,
                        "is_primary" => '1',
                        'last_login_at' => now()
                    ]);
                }

                $otp = '123456'; // Generate OTP here
                $mailTemp = EmailTemplate::where('slug', 'sendLoginOtp')->first();
                $html = Blade::render($mailTemp->body, [
                    'otp' => $otp,
                    'validity_minutes' => env('OTP_VALIDITY_MINUTES', 10)
                ]);
                Mail::to($request->email)->send(new MailTemp($html, $mailTemp->subject));
                EmailOtp::where('email', $request->email)->where('purpose', 'login')->update(['status' => '0']);
                EmailOtp::create([
                    "email" => $request->email,
                    "otp" => $otp,
                    "purpose" => 'login',
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
    public function login(Request $request)
    {
        try {
            if (isset($request->email) && isset($request->otp)) {
                $request->validate([
                    'email' => 'required|email',
                    'otp' => 'required',
                ]);
                $user = User::where(['email' => $request->email, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Email'], 500);
                }
                $otpRecord = EmailOtp::where('email', $user->email)
                    ->where('otp', $request->otp)
                    ->where('purpose', 'login')
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
                    'message' => 'Logged in successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

      public function dashboard(Request $request)
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
                $accounts = Account::where('user_id', $user->id)->get();
                foreach($accounts as $acc)
                {
                    $acc->transData7Days = Transaction::where([
                            'user_id'    => $user->id,
                            'account_id' => $acc->id
                        ])
                        ->where('transactionDate', '>=', Carbon::now()->subDays(7))
                        ->select(
                            DB::raw('DATE(transactionDate) as date'),
                            DB::raw("SUM(CASE WHEN transaction_type = 'income' THEN amount ELSE 0 END) as total_income"),
                            DB::raw("SUM(CASE WHEN transaction_type = 'expense' THEN amount ELSE 0 END) as total_expense")
                        )
                        ->groupBy(DB::raw('DATE(transactionDate)'))
                        ->orderBy('date', 'asc')
                        ->get();


                    $acc->transData30Days = Transaction::where(['transactions.user_id'=> $user->id,'account_id'=>$acc->id])
                        ->where('transactions.transactionDate', '>=', Carbon::now()->subDays(30))
                        ->join('categories', 'transactions.category_id', '=', 'categories.id')
                        ->select(
                            'categories.name as category_name',
                            DB::raw('SUM(transactions.amount) as total_amount'),
                            DB::raw("SUM(CASE WHEN transactions.transaction_type = 'income' THEN transactions.amount ELSE 0 END) as total_income"),
                            DB::raw("SUM(CASE WHEN transactions.transaction_type = 'expense' THEN transactions.amount ELSE 0 END) as total_expense")
                        )
                        ->groupBy('categories.name')
                        ->orderBy('categories.name', 'asc')
                        ->get();


                }

                $transactionDash = Transaction::where(['user_id'=> $user->id])->limit(5)->get();
                foreach($transactionDash as $trans)
                {
                    $categoryData = Category::where('id', $trans->category_id)->first();
                    $trans->categoryData = $categoryData;
                    $accountData = Account::where('id', $trans->account_id)->first();
                    $trans->accountData = $accountData;
                }

                return response()->json([
                    'status' => true,
                    'data' => [
                        'accounts'=>$accounts,
                        'transactions' => $transactionDash,
                        'user_details' => UserDetail::where('user_id', $user->id)->first(),
                        'kids'=>KidDetail::where('kid_details.parent_id', $user->id)
                            ->leftJoin('kid_accounts', function ($join) {
                                $join->on('kid_details.id', '=', 'kid_accounts.kid_id')
                                    ->where('kid_accounts.is_primary', 1);
                            })
                            ->select(
                                'kid_details.*',
                                'kid_accounts.id as account_id',
                                'kid_accounts.account_name',
                                'kid_accounts.default_currency',
                                'kid_accounts.balance'
                            )
                            ->get(),
                        'reminders'=>  Transaction::where(['user_id'=> $user->id,'transaction_type'=>'reminder'])->limit(5)->get(),
                    ],
                    'message' => 'Dashboard Fetched successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    // public function confirmPass(Request $request)
    // {
    //     try {
    //         if (isset($request->token)) {
    //             $request->validate([
    //                 'token' => 'required',
    //                 "newPass" => 'required',
    //                 "confirmPass" => 'required',
    //             ]);

    //             $user = User::where('remember_token', $request->token)->first();
    //             if (!$user) {
    //                 return response()->json(['status' => false, 'message' => 'User not found'], 404);
    //             }
    //             if($request->newPass !== $request->confirmPass){
    //                 return response()->json(['status' => false, 'message' => 'Password and Confirm Password do not match'], 400);
    //             }
    //             User::where('id', $user->id)->update(['email_verified_at' => now(), 'password' => Hash::make($request->newPass)]);
    //             return response()->json([
    //                 'status' => true,
    //                 'message' => 'Password created successfully',
    //             ]);

    //         } else {
    //             return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
    //         }
    //     } catch (\Exception $e) {
    //         return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
    //     }
    // }

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
                    "is_primary" => 0,
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
    public function getAccount(Request $request)
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
                $account = Account::where(['user_id' => $user->id, 'id' => $request->account_id, 'status' => 1])->first();
                return response()->json([
                    'status' => true,
                    'message' => 'Account fetched successfully',
                    'data' => $account
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
            if (isset($request->token) && isset($request->account_id) && isset($request->contributor_email) && isset($request->role)) {
                $request->validate([
                    'token' => 'required',
                    'account_id' => 'required|integer',
                    'contributor_email' => 'required|email',
                    'role' => 'required|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $contributorUser = User::where(['email' => $request->contributor_email, 'status' => 1])->first();
                 if (!$contributorUser) {
                    $contributor_name = explode('@', $request->contributor_email)[0];
                    $request->merge(['contributor_name' => $contributor_name]);

                    User::create([
                        "name" => $request->contributor_name,
                        "email" => $request->contributor_email,
                        "password" =>   hash::make('12346'),
                    ]);
                    $contributorUser = User::where('email', $request->contributor_email)->first();
                    UserDetail::create([
                        "user_id" => $contributorUser->id,
                        "name" => $request->contributor_name,
                        "email" => $request->contributor_email,
                    ]);
                    Account::create([
                        "user_id" => $contributorUser->id,
                        "account_name" => 'Main Account',
                        "default_currency" => 'INR',
                        "balance" => 0,
                        "is_primary" => '1',
                        'last_login_at' => now()
                    ]);
                }

                $mailTemp = EmailTemplate::where('slug', 'account-contributor-invite')->first();
                $html = Blade::render($mailTemp->body);
                Mail::to($request->email)->send(new MailTemp($html, $mailTemp->subject));
                MailLog::create([
                    'to_email' => $request->email,
                    'subject' => $mailTemp->subject,
                    'body' => $html,
                    'sent_at' => now(),
                ]);
                AccountContributor::create([
                    "account_id" => $request->account_id,
                    "contributor_id" => $contributorUser->id,
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
                foreach($contributors as $contributor){
                    $contributorData = UserDetail::where(['user_id' => $contributor->contributor_id, 'status' => 1])->first();
                    $contributor->contributorData = $contributorData;
                    $accountData = Account::where(['id' => $contributor->account_id, 'status' => 1])->first();
                    $contributor->accountData = $accountData;
                    $userData = UserDetail::where(['user_id' => $contributor->user_id, 'status' => 1])->first();
                    $contributor->userData = $userData;
                }
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
                $userCategories = UserCategory::where(['user_id' => $user->id])->get();
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
    public function getUserDetails(Request $request)
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
                $userDetails = UserDetail::where(['user_id' => $user->id, 'status' => 1])->first();
                return response()->json([
                    'status' => true,
                    'message' => 'User details fetched successfully',
                    'data' => $userDetails
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
            if (isset($request->token) && isset($request->name) && isset($request->phone) && isset($request->dob) && isset($request->currency)  && isset($request->country)) {
                $request->validate([
                    'name' => 'required|string',
                    'phone'=> 'required|string',
                    'dob'=> 'required|date',
                    'token' => 'required',
                    'currency' => 'required|string',
                    'country' => 'required|string',
                    'metadata' => 'nullable|string',
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
                UserDetail::where('user_id', $user->id)->update([
                    "name" => $request->name,
                    "phone" => $request->phone,
                    "dob" => $request->dob
                ]);
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

    public function inviteFriend(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->invitee_email)) {
                $request->validate([
                    'token' => 'required',
                    'invitee_email' => 'required|email',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }

                FriendInvite::create([
                    "inviter_user_id" => $user->id,
                    "invitee_email" => $request->invitee_email,
                    "invite_token"=> Str::uuid(),
                    "processStatus"=>"pending",
                    "status" => 1
                ]);

                $mailTemp = EmailTemplate::where('slug', 'friend-invite')->first();
                $html = Blade::render($mailTemp->body);
                Mail::to($request->invitee_email)->send(new MailTemp($html, $mailTemp->subject));
                MailLog::create([
                    'to_email' => $request->invitee_email,
                    'subject' => $mailTemp->subject,
                    'body' => $html,
                    'sent_at' => now(),
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Invitation sent successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function inviteFriendList(Request $request)
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
                $invitations = FriendInvite::where(['inviter_user_id' => $user->id])->get();

                return response()->json([
                    'status' => true,
                    'message' => 'Invitations Fetched successfully',
                    'data'=> $invitations
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function editInviteFriend(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->invite_id) && isset($request->invitee_email)) {
                $request->validate([
                    'token' => 'required',
                    'invite_id' => 'required|integer',
                    'invitee_email' => 'required|email',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                FriendInvite::where(['id' => $request->invite_id, 'inviter_user_id' => $user->id])->update([
                    "invitee_email" => $request->invitee_email,
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Invitation updated successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function resendInviteFriend(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->invite_id)) {
                $request->validate([
                    'token' => 'required',
                    'invite_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $invite = FriendInvite::where(['id' => $request->invite_id, 'inviter_user_id' => $user->id])->first();
                if(!$invite){
                    return response()->json(['status' => false, 'message' => 'Invitation not found'], 404);
                }

                $mailTemp = EmailTemplate::where('slug', 'friend-invite')->first();
                $html = Blade::render($mailTemp->body);
                Mail::to($invite->invitee_email)->send(new MailTemp($html, $mailTemp->subject));
                MailLog::create([
                    'to_email' => $invite->invitee_email,
                    'subject' => $mailTemp->subject,
                    'body' => $html,
                    'sent_at' => now(),
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Invitation resent successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function addTransaction(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->account_id) && isset($request->transaction_type) && isset($request->flow) && isset($request->amount) && isset($request->currency) && isset($request->category_id) && isset($request->transactionDate)) {
                $request->validate([
                    'token' => 'required',
                    'account_id' => 'required|integer',
                    'transaction_type' => 'required|string',
                    'transactionDate' => 'required',
                    'flow' => 'required|string',
                    'amount' => 'required|numeric',
                    'currency' => 'required|string',
                    'category_id'=> 'required|integer',
                    'target_account_id' => 'nullable|integer',
                    'contributor_id' => 'nullable|integer',
                    'description' => 'nullable|string',
                    'reference' => 'nullable|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                if($request->transaction_type === 'transfer'){
                    if(isset($request->target_account_id)){
                        $targetAccount = Account::where(['id' => $request->target_account_id, 'status' => 1])->first();
                        if($targetAccount){
                            $sourceAccount = Account::where(['id' => $request->account_id, 'status' => 1])->first();
                            if($sourceAccount){
                                if($sourceAccount->balance < $request->amount){
                                    return response()->json(['status' => false, 'message' => 'Insufficient balance in source account'], 400);
                                }else{
                                    $sourceAccount->balance -= $request->amount;
                                    $sourceAccount->save();
                                    $targetAccount->balance += $request->amount;
                                    $targetAccount->save();
                                }
                            }else{
                                return response()->json(['status' => false, 'message' => 'Source Account not found'], 404);
                            }
                        }else{
                            return response()->json(['status' => false, 'message' => 'Target Account not found'], 404);
                        }
                    }else{
                        return response()->json(['status' => false, 'message' => 'Target Account ID is required for transfer flow'], 400);
                    }
                }

                if($request->transaction_type === 'income' || $request->transaction_type === 'expense'){
                    $account = Account::where(['id' => $request->account_id, 'status' => 1])->first();
                    if($account){
                        if($request->transaction_type === 'income'){
                            $account->balance += $request->amount;
                        }else if($request->transaction_type === 'expense'){
                            if($account->balance < $request->amount){
                                return response()->json(['status' => false, 'message' => 'Insufficient balance in account'], 400);
                            }else{
                                $account->balance -= $request->amount;
                            }
                        }
                        $account->save();
                    }else{
                        return response()->json(['status' => false, 'message' => 'Account not found'], 404);
                    }
                }
                $transaction = Transaction::create([
                    "user_id" => $user->id,
                    "account_id" => $request->account_id,
                    "target_account_id" => $request->target_account_id,
                    "contributor_id" => $request->contributor_id,
                    "transaction_type" => $request->transaction_type,
                    "transactionDate" => $request->transactionDate,
                    "flow" => $request->flow,
                    "amount" => $request->amount,
                    "currency" => $request->currency,
                    "category_id" => $request->category_id,
                    "description" => $request->description,
                    "processStatus" => $request->transaction_type === 'reminder' ? 'pending' : 'completed',
                    "status" => 1,
                    "reference" => $request->reference,
                ]);

                if($request->transaction_type === 'reminder'){
                    if (isset($request->reminder_date) && isset($request->reminder_time) && isset($request->recurrence) && isset($request->notify_before_minutes)) {
                        $request->validate([
                            'reminder_date' => 'required|date',
                            'reminder_time' => 'required',
                            'recurrence' => 'required|string',
                            'notify_before_minutes' => 'required|integer',
                        ]);
                        ReminderPayment::create([
                            "transaction_id" => $transaction->id,
                            "reminder_date" => $request->reminder_date,
                            "reminder_time" => $request->reminder_time,
                            "recurrence" => $request->recurrence,
                            "notify_before_minutes" => $request->notify_before_minutes,
                            "status" => 1
                        ]);
                    }else{
                        return response()->json(['status' => false, 'message' => 'Empty Parameters for reminder transaction'], 400);
                    }
                }

                return response()->json([
                    'status' => true,
                    'message' => 'Transaction added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getTransaction(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->transaction_id)) {
                $request->validate([
                    'token' => 'required',
                    'transaction_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = Transaction::where(['id' => $request->transaction_id, 'user_id' => $user->id, 'status' => 1])->first();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                $transaction->categoryData = Category::where(['id' => $transaction->category_id, 'status' => 1])->first();
                if($transaction->transaction_type === 'reminder'){
                    $reminderPayment = ReminderPayment::where(['transaction_id' => $transaction->id, 'status' => 1])->first();
                    $transaction->reminderPayment = $reminderPayment;
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Transaction fetched successfully',
                    'data' => $transaction
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function getTransactionList(Request $request)
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

                $currentAccount = Account::where(['user_id'=> $user->id,'id'=>$request->account_id])->first();
                $currentAccount->list = new \stdClass();
                $currentAccount->stats = new \stdClass();

               $currentAccount->list->transData7Days = Transaction::where([
                    'account_id' => $request->account_id,
                    'user_id'    => $user->id,
                    'status'     => 1
                ])
                ->where('transactionDate', '>=', Carbon::now()->subDays(7)) // ✅ operator goes here
                ->orderBy('transactionDate', 'desc')
                ->get();
                if(!$currentAccount->list->transData7Days){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                foreach ($currentAccount->list->transData7Days as $item) {
                    $item->categoryData = Category::where(['id' => $item->category_id, 'status' => 1])->first();
                    if($item->transaction_type === 'reminder'){
                        $reminderPayment = ReminderPayment::where(['transaction_id' => $item->id, 'status' => 1])->first();
                        $item->reminderPayment = $reminderPayment;
                    }
                }


                 $currentAccount->list->transDatacurrentMonth = Transaction::where(['account_id' => $request->account_id, 'user_id' => $user->id, 'status' => 1])->whereBetween('transactionDate', [
                        Carbon::now()->startOfMonth(),
                        Carbon::now()->endOfMonth()
                    ])
                    ->orderBy('transactionDate', 'desc')
                    ->get();
                if(!$currentAccount->list->transDatacurrentMonth){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                foreach ($currentAccount->list->transDatacurrentMonth as $item) {
                    $item->categoryData = Category::where(['id' => $item->category_id, 'status' => 1])->first();
                    if($item->transaction_type === 'reminder'){
                        $reminderPayment = ReminderPayment::where(['transaction_id' => $item->id, 'status' => 1])->first();
                        $item->reminderPayment = $reminderPayment;
                    }
                }

                $currentAccount->stats->transData7Days = Transaction::where([
                        'user_id'    => $user->id,
                        'account_id' => $currentAccount->id
                    ])
                    ->where('transactionDate', '>=', Carbon::now()->subDays(7))
                    ->select(
                        DB::raw('DATE(transactionDate) as date'),
                        DB::raw("SUM(CASE WHEN transaction_type = 'income' THEN amount ELSE 0 END) as total_income"),
                        DB::raw("SUM(CASE WHEN transaction_type = 'expense' THEN amount ELSE 0 END) as total_expense")
                    )
                    ->groupBy(DB::raw('DATE(transactionDate)'))
                    ->orderBy('date', 'desc')
                    ->get();


               $currentAccount->stats->transDatacurrentMonth = Transaction::where([
                        'transactions.user_id' => $user->id,
                        'account_id'           => $currentAccount->id
                    ])
                    ->whereBetween('transactionDate', [
                        Carbon::now()->startOfMonth(),
                        Carbon::now()->endOfMonth()
                    ])
                    ->join('categories', 'transactions.category_id', '=', 'categories.id')
                    ->select(
                        'categories.name as category_name',
                        DB::raw('SUM(transactions.amount) as total_amount'),
                        DB::raw("SUM(CASE WHEN transactions.transaction_type = 'income' THEN transactions.amount ELSE 0 END) as total_income"),
                        DB::raw("SUM(CASE WHEN transactions.transaction_type = 'expense' THEN transactions.amount ELSE 0 END) as total_expense")
                    )
                    ->groupBy('categories.name')
                    ->orderBy('categories.name', 'desc')
                    ->get();


                return response()->json([
                    'status' => true,
                    'message' => 'Transaction fetched successfully',
                    'data' => $currentAccount
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getTransactionListCustom(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->account_id) && isset($request->start_date) && isset($request->end_date) && isset($request->type)) {
                $request->validate([
                    'token' => 'required',
                    'account_id' => 'required|integer',
                    'start_date' => 'required|date',
                    'end_date' => 'required|date',
                    'type' => 'required|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $currentAccount = Account::where(['user_id'=> $user->id,'id'=>$request->account_id])->first();
                $currentAccount->list = new \stdClass();
                $currentAccount->stats = new \stdClass();
                if($request->type === 'list'){
                   $currentAccount->list->custom = Transaction::where([
                            'account_id' => $request->account_id,
                            'user_id'    => $user->id,
                            'status'     => 1
                        ])
                        ->whereBetween('transactionDate', [$request->start_date, $request->end_date]) // ✅ filter by start & end date
                        ->orderBy('transactionDate', 'desc')
                        ->get();

                    if ($currentAccount->list->custom->isEmpty()) {
                        return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                    }

                    foreach ($currentAccount->list->custom as $item) {
                        $item->categoryData = Category::where([
                            'id'     => $item->category_id,
                            'status' => 1
                        ])->first();

                        if ($item->transaction_type === 'reminder') {
                            $item->reminderPayment = ReminderPayment::where([
                                'transaction_id' => $item->id,
                                'status'         => 1
                            ])->first();
                        }
                    }
                }elseif($request->type === 'stats')
                {
                   $currentAccount->stats->custom = Transaction::where([
                        'transactions.user_id' => $user->id,
                        'account_id'           => $currentAccount->id
                    ])
                    ->whereBetween('transactions.transactionDate', [
                        $request->start_date,
                        $request->end_date
                    ])
                    ->join('categories', 'transactions.category_id', '=', 'categories.id')
                    ->select(
                        'categories.name as category_name',
                        DB::raw('SUM(transactions.amount) as total_amount'),
                        DB::raw("SUM(CASE WHEN transactions.transaction_type = 'income' THEN transactions.amount ELSE 0 END) as total_income"),
                        DB::raw("SUM(CASE WHEN transactions.transaction_type = 'expense' THEN transactions.amount ELSE 0 END) as total_expense")
                    )
                    ->groupBy('categories.name')
                    ->orderBy('categories.name', 'desc')
                    ->get();

                }else{
                    return response()->json(['status' => false, 'message' => 'Please Select a Type'], 400);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Transaction list fetched successfully',
                    'data' => $currentAccount
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function deleteTransaction(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->transaction_id)) {
                $request->validate([
                    'token' => 'required',
                    'transaction_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = Transaction::where(['id' => $request->transaction_id, 'user_id' => $user->id, 'status' => 1])->first();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                if($transaction->transaction_type === 'reminder'){
                    $reminderPayment = ReminderPayment::where(['transaction_id' => $transaction->id, 'status' => 1])->first();
                    if($reminderPayment){
                        $reminderPayment->update(['status' => 0]);
                    }
                }
                if($transaction->transaction_type === 'transfer'){
                    $sourceAccount = Account::where(['id' => $transaction->account_id, 'status' => 1])->first();
                    $targetAccount = Account::where(['id' => $transaction->target_account_id, 'status' => 1])->first();
                    if($sourceAccount && $targetAccount){
                        if($transaction->flow === 'debit'){
                            $targetAccount->balance -= $transaction->amount;
                            $sourceAccount->balance += $transaction->amount;
                        }else if($transaction->flow === 'credit'){
                            $targetAccount->balance += $transaction->amount;
                            $sourceAccount->balance -= $transaction->amount;
                        }
                        $sourceAccount->save();
                        $targetAccount->save();
                    }
                }
                if($transaction->transaction_type === 'income' || $transaction->transaction_type === 'expense'){
                    $account = Account::where(['id' => $transaction->account_id, 'status' => 1])->first();
                    if($account){
                        if($transaction->transaction_type === 'income'){
                            $account->balance -= $transaction->amount;
                        }else if($transaction->transaction_type === 'expense'){
                            $account->balance += $transaction->amount;
                        }
                        $account->save();
                    }
                }
                $transaction->update(['status' => 0]);
                return response()->json([
                    'status' => true,
                    'message' => 'Transaction deleted successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function editTransaction(Request $request)
    {
        try {
            if (isset($request->transaction_id) && isset($request->token) && isset($request->account_id) && isset($request->transaction_type) && isset($request->flow) && isset($request->amount) && isset($request->currency) && isset($request->category_id) && isset($request->transactionDate)) {
                $request->validate([
                    'transaction_id' => 'required|integer',
                    'token' => 'required',
                    'account_id' => 'required|integer',
                    'transaction_type' => 'required|string',
                    'transactionDate' => 'required',
                    'flow' => 'required|string',
                    'amount' => 'required|numeric',
                    'currency' => 'required|string',
                    'category_id' => 'required|integer',
                    'target_account_id' => 'nullable|integer',
                    'contributor_id' => 'nullable|integer',
                    'description' => 'nullable|string',
                    'reference' => 'nullable|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = Transaction::where(['id' => $request->transaction_id, 'user_id' => $user->id, 'status' => 1])->first();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                // Revert previous transaction effects first
                $prevAmount = $transaction->amount;
                $prevType = $transaction->transaction_type;
                $prevAccountId = $transaction->account_id;
                $prevTargetId = $transaction->target_account_id;
                $prevFlow = $transaction->flow;

                if($prevType === 'transfer'){
                    $sourcePrev = Account::where(['id' => $prevAccountId, 'status' => 1])->first();
                    $targetPrev = Account::where(['id' => $prevTargetId, 'status' => 1])->first();
                    if($sourcePrev && $targetPrev){
                        if($prevFlow === 'debit'){
                            $targetPrev->balance -= $prevAmount;
                            $sourcePrev->balance += $prevAmount;
                        }else if($prevFlow === 'credit'){
                            $targetPrev->balance += $prevAmount;
                            $sourcePrev->balance -= $prevAmount;
                        }else{
                            // fallback reverse assuming original add used account_id as source
                            $sourcePrev->balance += $prevAmount;
                            $targetPrev->balance -= $prevAmount;
                        }
                        $sourcePrev->save();
                        $targetPrev->save();
                    }
                } elseif($prevType === 'income' || $prevType === 'expense'){
                    $accPrev = Account::where(['id' => $prevAccountId, 'status' => 1])->first();
                    if($accPrev){
                        if($prevType === 'income'){
                            $accPrev->balance -= $prevAmount;
                        }else{
                            $accPrev->balance += $prevAmount;
                        }
                        $accPrev->save();
                    }
                }

                if($request->transaction_type === 'transfer'){
                    if(isset($request->target_account_id)){
                        $targetAccount = Account::where(['id' => $request->target_account_id, 'status' => 1])->first();
                        if($targetAccount){
                            $sourceAccount = Account::where(['id' => $request->account_id, 'status' => 1])->first();
                            if($sourceAccount){
                                if($sourceAccount->balance < $request->amount){
                                    return response()->json(['status' => false, 'message' => 'Insufficient balance in source account'], 400);
                                }else{
                                    $sourceAccount->balance -= $request->amount;
                                    $sourceAccount->save();
                                    $targetAccount->balance += $request->amount;
                                    $targetAccount->save();
                                }
                            }else{
                                return response()->json(['status' => false, 'message' => 'Source Account not found'], 404);
                            }
                        }else{
                            return response()->json(['status' => false, 'message' => 'Target Account not found'], 404);
                        }
                    }else{
                        return response()->json(['status' => false, 'message' => 'Target Account ID is required for transfer flow'], 400);
                    }
                }

                if($request->transaction_type === 'income' || $request->transaction_type === 'expense'){
                    $account = Account::where(['id' => $request->account_id, 'status' => 1])->first();
                    if($account){
                        if($request->transaction_type === 'income'){
                            $account->balance += $request->amount;
                        }else if($request->transaction_type === 'expense'){
                            if($account->balance < $request->amount){
                                return response()->json(['status' => false, 'message' => 'Insufficient balance in account'], 400);
                            }else{
                                $account->balance -= $request->amount;
                            }
                        }
                        $account->save();
                    }else{
                        return response()->json(['status' => false, 'message' => 'Account not found'], 404);
                    }
                }
                Transaction::where(['id' => $request->transaction_id])->update([
                    "user_id" => $user->id,
                    "account_id" => $request->account_id,
                    "target_account_id" => $request->target_account_id,
                    "contributor_id" => $request->contributor_id,
                    "transaction_type" => $request->transaction_type,
                    "transactionDate" => $request->transactionDate,
                    "flow" => $request->flow,
                    "amount" => $request->amount,
                    "currency" => $request->currency,
                    "category_id" => $request->category_id,
                    "description" => $request->description,
                    "processStatus" => $request->transaction_type === 'reminder' ? 'pending' : 'completed',
                    "status" => 1,
                    "reference" => $request->reference,
                ]);
                if($request->transaction_type === 'reminder'){
                    if (isset($request->reminder_date) && isset($request->reminder_time) && isset($request->recurrence) && isset($request->notify_before_minutes)) {
                        $request->validate([
                            'reminder_date' => 'required|date',
                            'reminder_time' => 'required',
                            'recurrence' => 'required|string',
                            'notify_before_minutes' => 'required|integer',
                        ]);
                        ReminderPayment::where(['transaction_id' => $request->transaction_id])->update([
                            "transaction_id" => $request->transaction_id,
                            "reminder_date" => $request->reminder_date,
                            "reminder_time" => $request->reminder_time,
                            "recurrence" => $request->recurrence,
                            "notify_before_minutes" => $request->notify_before_minutes,
                            "status" => 1
                        ]);
                    }else{
                        return response()->json(['status' => false, 'message' => 'Empty Parameters for reminder transaction'], 400);
                    }
                }

                return response()->json([
                    'status' => true,
                    'message' => 'Transaction updated successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function addKid(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->name) && isset($request->relation) && isset($request->dob) && isset($request->email)) {
                $request->validate([
                    'token' => 'required',
                    'name' => 'required|string',
                    'relation' => 'required|string',
                    'dob' => 'required|date',
                    'email' => 'required|email',
                    'userName' => 'nullable|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $uniqueId =strtoupper(Str::random(4)) .rand('0000','9999');
                while(KidDetail::where('unique_Id', $uniqueId)->exists()){
                    $uniqueId =strtoupper(Str::random(4)) .rand('0000','9999');
                }
                if(isset($request->userName)){
                    $userNameExist = KidDetail::where('userName', $request->userName)->exists();
                    if($userNameExist){
                        return response()->json(['status' => false, 'message' => 'UserName Taken'], 400);
                    }
                }

                KidDetail::create([
                    "parent_id" => $user->id,
                    "unique_Id" => $uniqueId,
                    "name" => $request->name,
                    "userName" => $request->userName ?? NULL,
                    "relation" => $request->relation,
                    "date_of_birth" => $request->dob,
                    "email" => $request->email,
                    'password' => Hash::make("kid@123"),
                ]);

                $kid = KidDetail::where(['parent_id' => $user->id, 'unique_Id' => $uniqueId])->first();
                KidAccount::create([
                    "parent_id" => $user->id,
                    "kid_id" => $kid->id,
                    "account_name" => 'Main Account',
                    "default_currency" => 'INR',
                    "balance" => 0,
                    "is_primary" => '1',
                    'last_login_at' => now()
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Kid added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function editKid(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->name) && isset($request->relation) && isset($request->dob) && isset($request->email)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                    'name' => 'required|string',
                    'relation' => 'required|string',
                    'dob' => 'required|date',
                    'email' => 'required|email',
                    'userName' => 'nullable|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                    return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                KidDetail::where(['id' => $request->kid_id])->update([
                    "name" => $request->name,
                    "userName" => $request->userName ?? NULL,
                    "relation" => $request->relation,
                    "date_of_birth" => $request->dob,
                    "email" => $request->email,
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Kid Edited successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getKidDetails(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                    return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                $kid->account = KidAccount::where(['kid_id' => $kid->id, 'is_primary' => 1])->first(['id', 'account_name', 'default_currency', 'balance']);
                return response()->json([
                    'status' => true,
                    'message' => 'Kid details fetched successfully',
                    'data' => $kid
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function addKidTask(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->task_name) && isset($request->description) && isset($request->frequency) && isset($request->reward_amount)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                    'task_name' => 'required|string',
                    'description' => 'nullable|string',
                    'frequency' => 'required|string',
                    'reward_amount' => 'required|numeric',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }

                KidTask::create([
                    "parent_id" => $user->id,
                    "kid_id" => $kid->id,
                    "task_name" => $request->task_name,
                    "description" => $request->description ?? NULL,
                    "frequency" => $request->frequency,
                    "reward_amount" => $request->reward_amount,
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Task added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function editKidTask(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->task_id) && isset($request->kid_id) && isset($request->task_name) && isset($request->description) && isset($request->frequency) && isset($request->reward_amount)) {
                $request->validate([
                    'token' => 'required',
                    'task_id' => 'required|integer',
                    "kid_id" => 'required|integer',
                    'task_name' => 'required|string',
                    'description' => 'nullable|string',
                    'frequency' => 'required|string',
                    'reward_amount' => 'required|numeric',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }

                KidTask::where('id', $request->task_id)->update([
                    "parent_id" => $user->id,
                    "kid_id" => $kid->id,
                    "task_name" => $request->task_name,
                    "description" => $request->description ?? NULL,
                    "frequency" => $request->frequency,
                    "reward_amount" => $request->reward_amount,
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Task updated successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function deleteKidTask(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->task_id) && isset($request->kid_id)) {
                $request->validate([
                    'token' => 'required',
                    'task_id' => 'required|integer',
                    "kid_id" => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }

                KidTask::where('id', $request->task_id)->update([
                    "status" => 0,
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Task Deleted successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function getKidTask(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                $tasks = KidTask::where(['kid_id' => $kid->id, 'status' => '1'])->get();
                return response()->json([
                    'status' => true,
                    'message' => 'Tasks fetched successfully',
                    'data' => $tasks,
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getKidTaskDetails(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->task_id)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                    "task_id" => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                    return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                $tasks = KidTask::where(['kid_id' => $kid->id, 'id' => $request->task_id])->first();
                return response()->json([
                    'status' => true,
                    'message' => 'Tasks fetched successfully',
                    'data' => $tasks,
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }



    public function addKidGoal(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->goal_name) && isset($request->target_amount) && isset($request->target_date)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                    'goal_name' => 'required|string',
                    'target_amount' => 'required|numeric',
                    'target_date' => 'required|date',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                KidGoal::create([
                    "parent_id" => $user->id,
                    "kid_id" => $kid->id,
                    "goal_name" => $request->goal_name,
                    "target_amount" => $request->target_amount,
                    "target_date" => $request->target_date,
                ]);

                return response()->json([
                    'status' => true,
                    'message' => 'Goal added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

     public function editKidGoal(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->goal_id) && isset($request->goal_name) && isset($request->target_amount) && isset($request->target_date)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                    "goal_id" => 'required|integer',
                    'goal_name' => 'required|string',
                    'target_amount' => 'required|numeric',
                    'target_date' => 'required|date',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                    return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                KidGoal::where('id', $request->goal_id)->update([
                    "parent_id" => $user->id,
                    "kid_id" => $kid->id,
                    "goal_name" => $request->goal_name,
                    "target_amount" => $request->target_amount,
                    "target_date" => $request->target_date,
                ]);

                return response()->json([
                    'status' => true,
                    'message' => 'Goal updated successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function deleteKidGoal(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->goal_id)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                    "goal_id" => 'required|integer'
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                    return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                KidGoal::where('id', $request->goal_id)->update([
                    "status" => 0,
                ]);

                return response()->json([
                    'status' => true,
                    'message' => 'Goal deleted successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getKidGoal(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                $goals = KidGoal::where(['kid_id' => $kid->id, 'status' => '1'])->get();
                return response()->json([
                    'status' => true,
                    'message' => 'Goals fetched successfully',
                    'data' => $goals,
                ]);
            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
    public function getKidGoalDetails(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->goal_id)) {
                $request->validate([
                    'token' => 'required',
                    "kid_id" => 'required|integer',
                    "goal_id" => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                return response()->json(['status' => false, 'message' => 'Kid not found'], 400);
                }
                $goal = KidGoal::where(['kid_id' => $kid->id, 'id' => $request->goal_id, 'status' => '1'])->first();
                return response()->json([
                    'status' => true,
                    'message' => 'Goals fetched successfully',
                    'data' => $goal,
                ]);
            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getKidDetailList(Request $request)
    {
        try {
            if(isset($request->token)){
                $request->validate([
                    'token' => 'required',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kidDetails = KidDetail::select(['id', 'name', 'email', 'relation'])->where(['parent_id' => $user->id])->get();

                foreach($kidDetails as $kid){
                    $kid->account = KidAccount::where(['kid_id' => $kid->id, 'is_primary' => 1])->first(['id', 'account_name', 'default_currency', 'balance']);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Kid Details fetched successfully',
                    'data' => $kidDetails,
                ]);
            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }

        } catch (\Throwable $th) {
            return response()->json(['status' => false, 'message' => $th->getMessage()], 500);
        }
    }

    public function addKidTransaction(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->transaction_type) && isset($request->flow) && isset($request->amount) && isset($request->currency) && isset($request->transactionDate)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                    'transaction_type' => 'required|string',
                    'transactionDate' => 'required',
                    'flow' => 'required|string',
                    'amount' => 'required|numeric',
                    'currency' => 'required|string',
                    'description' => 'nullable|string',
                    'source_account_id' => 'nullable|integer',
                    'reference' => 'nullable|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $kid = KidDetail::where(['id' => $request->kid_id,'parent_id' => $user->id])->first();
                if (!$kid) {
                    return response()->json(['status' => false, 'message' => 'Kid not found'], 404);
                }
                if($request->transaction_type === 'income'){
                    if(isset($request->source_account_id)){
                        $targetAccount = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                        if($targetAccount){
                            $sourceAccount = Account::where(['id' => $request->source_account_id, 'status' => 1])->first();
                            if($sourceAccount){
                                if($sourceAccount->balance < $request->amount){
                                    return response()->json(['status' => false, 'message' => 'Insufficient balance in source account'], 400);
                                }else{
                                    $sourceAccount->balance -= $request->amount;
                                    $sourceAccount->save();
                                    $targetAccount->balance += $request->amount;
                                    $targetAccount->save();
                                }
                            }else{
                                return response()->json(['status' => false, 'message' => 'Source Account not found'], 404);
                            }
                        }else{
                            return response()->json(['status' => false, 'message' => 'Target Account not found'], 404);
                        }
                    }else{
                        return response()->json(['status' => false, 'message' => 'Target Account ID is required for transfer flow'], 400);
                    }
                }

                if($request->transaction_type === 'expense'){
                    $source_account_id = Account::where(['is_primary' => '1', 'status' => 1])->first();
                    $request->merge(['source_account_id' => $source_account_id->id]);
                    $account = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                    if($account){
                        if($account->balance < $request->amount){
                            return response()->json(['status' => false, 'message' => 'Insufficient balance in account'], 400);
                        }else{
                            $account->balance -= $request->amount;
                        }
                        $account->save();
                    }else{
                        return response()->json(['status' => false, 'message' => 'Account not found'], 404);
                    }
                }
                $kidtransaction = KidTransaction::create([
                    "parent_id" => $user->id,
                    "kid_id" => $request->kid_id,
                    "parent_account_id" => $request->source_account_id,
                    "transaction_type" => $request->transaction_type,
                    "transactionDate" => $request->transactionDate,
                    "flow" => $request->flow,
                    "amount" => $request->amount,
                    "currency" => $request->currency,
                    "description" => $request->description,
                    "status" => 1,
                    "reference" => $request->reference ?? NULL,
                ]);

                return response()->json([
                    'status' => true,
                    'message' => 'Kid Transaction added successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getKidTransactionList(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = KidTransaction::where(['kid_id' => $request->kid_id, 'parent_id' => $user->id, 'status' => 1])->get();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Transaction fetched successfully',
                    'data' => $transaction
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getKidTransactionDetail(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->transaction_id)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                    'transaction_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = KidTransaction::where(['id' => $request->transaction_id, 'kid_id' => $request->kid_id, 'parent_id' => $user->id, 'status' => 1])->first();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Transaction fetched successfully',
                    'data' => $transaction
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function deleteKidTransaction(Request $request)
    {
        try {
            if (isset($request->token) && isset($request->kid_id) && isset($request->transaction_id)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                    'transaction_id' => 'required|integer',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = KidTransaction::where(['id' => $request->transaction_id, 'kid_id' => $request->kid_id, 'parent_id' => $user->id, 'status' => 1])->first();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                if($transaction->transaction_type === 'income'){
                    $sourceAccount = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                    $targetAccount = Account::where(['id' => $transaction->parent_account_id, 'status' => 1])->first();
                    if($sourceAccount && $targetAccount){
                        $targetAccount->balance += $transaction->amount;
                        $sourceAccount->balance -= $transaction->amount;
                        $sourceAccount->save();
                        $targetAccount->save();
                    }
                }
                if($transaction->transaction_type === 'expense'){
                    $account = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                    if($account){
                        $account->balance += $transaction->amount;
                        $account->save();
                    }
                }
                $transaction->update(['status' => 0]);
                return response()->json([
                    'status' => true,
                    'message' => 'Transaction deleted successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function editKidTransaction(Request $request)
    {
        try {
            if (isset($request->transaction_id) && isset($request->token) && isset($request->kid_id) && isset($request->transaction_type) && isset($request->flow) && isset($request->amount) && isset($request->currency) && isset($request->transactionDate)) {
                $request->validate([
                    'token' => 'required',
                    'kid_id' => 'required|integer',
                    'transaction_type' => 'required|string',
                    'transactionDate' => 'required',
                    'flow' => 'required|string',
                    'amount' => 'required|numeric',
                    'currency' => 'required|string',
                    'description' => 'nullable|string',
                    'source_account_id' => 'nullable|integer',
                    'reference' => 'nullable|string',
                ]);
                $user = User::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$user) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                $transaction = KidTransaction::where(['kid_id' => $request->kid_id, 'parent_id' => $user->id, 'status' => 1])->get();
                if(!$transaction){
                    return response()->json(['status' => false, 'message' => 'Transaction not found'], 404);
                }
                // Revert previous transaction effects first
                $prevAmount = $transaction->amount;
                $prevType = $transaction->transaction_type;
                $prevTargetId = $transaction->parent_account_id;
                $prevFlow = $transaction->flow;

                if($prevType === 'transfer'){
                    $sourcePrev = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                    $targetPrev = Account::where(['id' => $prevTargetId, 'status' => 1])->first();
                    if($sourcePrev && $targetPrev){
                        $targetPrev->balance += $prevAmount;
                        $sourcePrev->balance -= $prevAmount;
                        $sourcePrev->save();
                        $targetPrev->save();
                    }
                } elseif($prevType === 'expense'){
                    $accPrev = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                    if($accPrev){
                        $accPrev->balance += $prevAmount;
                        $accPrev->save();
                    }
                }

              if($request->transaction_type === 'income'){
                    if(isset($request->source_account_id)){
                        $targetAccount = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                        if($targetAccount){
                            $sourceAccount = Account::where(['id' => $request->source_account_id, 'status' => 1])->first();
                            if($sourceAccount){
                                if($sourceAccount->balance < $request->amount){
                                    return response()->json(['status' => false, 'message' => 'Insufficient balance in source account'], 400);
                                }else{
                                    $sourceAccount->balance -= $request->amount;
                                    $sourceAccount->save();
                                    $targetAccount->balance += $request->amount;
                                    $targetAccount->save();
                                }
                            }else{
                                return response()->json(['status' => false, 'message' => 'Source Account not found'], 404);
                            }
                        }else{
                            return response()->json(['status' => false, 'message' => 'Target Account not found'], 404);
                        }
                    }else{
                        return response()->json(['status' => false, 'message' => 'Target Account ID is required for transfer flow'], 400);
                    }
                }

                if($request->transaction_type === 'expense'){
                    $account = KidAccount::where(['kid_id' => $request->kid_id, 'status' => 1])->first();
                    if($account){
                        if($account->balance < $request->amount){
                            return response()->json(['status' => false, 'message' => 'Insufficient balance in account'], 400);
                        }else{
                            $account->balance -= $request->amount;
                        }
                        $account->save();
                    }else{
                        return response()->json(['status' => false, 'message' => 'Account not found'], 404);
                    }
                }
                $kidtransaction = KidTransaction::where(['id' => $request->transaction_id])->update([
                    "parent_id" => $user->id,
                    "kid_id" => $request->kid_id,
                    "parent_account_id" => $request->source_account_id ?? NULL,
                    "transaction_type" => $request->transaction_type,
                    "transactionDate" => $request->transactionDate,
                    "flow" => $request->flow,
                    "amount" => $request->amount,
                    "currency" => $request->currency,
                    "description" => $request->description,
                    "status" => 1,
                    "reference" => $request->reference ?? NULL,
                ]);

                return response()->json([
                    'status' => true,
                    'message' => 'Transaction updated successfully',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

}
